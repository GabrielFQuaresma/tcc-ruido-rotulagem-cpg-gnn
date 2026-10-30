# Pacote de anotacao — caso 45

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

# Evidencia do caso 45

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `coders/dpx.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -480,6 +480,12 @@
        (void) CloseBlob(image);
        return(GetFirstImageInList(image));
      }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
    for (n=0; n < (ssize_t) dpx.image.number_elements; n++)
    {
      /*
```

## Corpo completo da funcao antes da correcao

```c
static Image *ReadDPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
{
  char
    magick[4],
    value[MaxTextExtent];

  DPXInfo
    dpx;

  Image
    *image;

  MagickBooleanType
    status;

  MagickOffsetType
    offset;

  QuantumInfo
    *quantum_info;

  QuantumType
    quantum_type;

  register ssize_t
    i;

  size_t
    extent,
    samples_per_pixel;

  ssize_t
    count,
    n,
    row,
    y;

  unsigned char
    component_type;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  /*
    Read DPX file header.
  */
  offset=0;
  count=ReadBlob(image,4,(unsigned char *) magick);
  offset+=count;
  if ((count != 4) || ((LocaleNCompare(magick,"SDPX",4) != 0) &&
      (LocaleNCompare((char *) magick,"XPDS",4) != 0)))
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  image->endian=LSBEndian;
  if (LocaleNCompare(magick,"SDPX",4) == 0)
    image->endian=MSBEndian;
  (void) ResetMagickMemory(&dpx,0,sizeof(dpx));
  dpx.file.image_offset=ReadBlobLong(image);
  offset+=4;
  offset+=ReadBlob(image,sizeof(dpx.file.version),(unsigned char *)
    dpx.file.version);
  (void) FormatImageProperty(image,"dpx:file.version","%.8s",dpx.file.version);
  dpx.file.file_size=ReadBlobLong(image);
  offset+=4;
  dpx.file.ditto_key=ReadBlobLong(image);
  offset+=4;
  if (dpx.file.ditto_key != ~0U)
    (void) FormatImageProperty(image,"dpx:file.ditto.key","%u",
      dpx.file.ditto_key);
  dpx.file.generic_size=ReadBlobLong(image);
  offset+=4;
  dpx.file.industry_size=ReadBlobLong(image);
  offset+=4;
  dpx.file.user_size=ReadBlobLong(image);
  offset+=4;
  offset+=ReadBlob(image,sizeof(dpx.file.filename),(unsigned char *)
    dpx.file.filename);
  (void) FormatImageProperty(image,"dpx:file.filename","%.100s",
    dpx.file.filename);
  (void) FormatImageProperty(image,"document","%.100s",dpx.file.filename);
  offset+=ReadBlob(image,sizeof(dpx.file.timestamp),(unsigned char *)
    dpx.file.timestamp);
  if (*dpx.file.timestamp != '\0')
    (void) FormatImageProperty(image,"dpx:file.timestamp","%.24s",
      dpx.file.timestamp);
  offset+=ReadBlob(image,sizeof(dpx.file.creator),(unsigned char *)
    dpx.file.creator);
  if (*dpx.file.creator == '\0')
    {
      (void) FormatImageProperty(image,"dpx:file.creator","%.100s",
        GetMagickVersion((size_t *) NULL));
      (void) FormatImageProperty(image,"software","%.100s",
        GetMagickVersion((size_t *) NULL));
    }
  else
    {
      (void) FormatImageProperty(image,"dpx:file.creator","%.100s",
        dpx.file.creator);
      (void) FormatImageProperty(image,"software","%.100s",dpx.file.creator);
    }
  offset+=ReadBlob(image,sizeof(dpx.file.project),(unsigned char *)
    dpx.file.project);
  if (*dpx.file.project != '\0')
    {
      (void) FormatImageProperty(image,"dpx:file.project","%.200s",
        dpx.file.project);
      (void) FormatImageProperty(image,"comment","%.100s",dpx.file.project);
    }
  offset+=ReadBlob(image,sizeof(dpx.file.copyright),(unsigned char *)
    dpx.file.copyright);
  if (*dpx.file.copyright != '\0')
    {
      (void) FormatImageProperty(image,"dpx:file.copyright","%.200s",
        dpx.file.copyright);
      (void) FormatImageProperty(image,"copyright","%.100s",
        dpx.file.copyright);
    }
  dpx.file.encrypt_key=ReadBlobLong(image);
  offset+=4;
  if (dpx.file.encrypt_key != ~0U)
    (void) FormatImageProperty(image,"dpx:file.encrypt_key","%u",
      dpx.file.encrypt_key);
  offset+=ReadBlob(image,sizeof(dpx.file.reserve),(unsigned char *)
    dpx.file.reserve);
  /*
    Read DPX image header.
  */
  dpx.image.orientation=ReadBlobShort(image);
  if (dpx.image.orientation > 7)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  offset+=2;
  if (dpx.image.orientation != (unsigned short) ~0)
    (void) FormatImageProperty(image,"dpx:image.orientation","%d",
      dpx.image.orientation);
  switch (dpx.image.orientation)
  {
    default:
    case 0: image->orientation=TopLeftOrientation; break;
    case 1: image->orientation=TopRightOrientation; break;
    case 2: image->orientation=BottomLeftOrientation; break;
    case 3: image->orientation=BottomRightOrientation; break;
    case 4: image->orientation=LeftTopOrientation; break;
    case 5: image->orientation=RightTopOrientation; break;
    case 6: image->orientation=LeftBottomOrientation; break;
    case 7: image->orientation=RightBottomOrientation; break;
  }
  dpx.image.number_elements=ReadBlobShort(image);
  if (dpx.image.number_elements > MaxNumberImageElements)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  offset+=2;
  dpx.image.pixels_per_line=ReadBlobLong(image);
  offset+=4;
  image->columns=dpx.image.pixels_per_line;
  dpx.image.lines_per_element=ReadBlobLong(image);
  offset+=4;
  image->rows=dpx.image.lines_per_element;
  for (i=0; i < 8; i++)
  {
    char
      property[MaxTextExtent];

    dpx.image.image_element[i].data_sign=ReadBlobLong(image);
    offset+=4;
    dpx.image.image_element[i].low_data=ReadBlobLong(image);
    offset+=4;
    dpx.image.image_element[i].low_quantity=ReadBlobFloat(image);
    offset+=4;
    dpx.image.image_element[i].high_data=ReadBlobLong(image);
    offset+=4;
    dpx.image.image_element[i].high_quantity=ReadBlobFloat(image);
    offset+=4;
    dpx.image.image_element[i].descriptor=(unsigned char) ReadBlobByte(image);
    offset++;
    dpx.image.image_element[i].transfer_characteristic=(unsigned char)
      ReadBlobByte(image);
    (void) FormatLocaleString(property,MaxTextExtent,
      "dpx:image.element[%lu].transfer-characteristic",(long) i);
    (void) FormatImageProperty(image,property,"%s",
      GetImageTransferCharacteristic((DPXTransferCharacteristic)
      dpx.image.image_element[i].transfer_characteristic));
    offset++;
    dpx.image.image_element[i].colorimetric=(unsigned char) ReadBlobByte(image);
    offset++;
    dpx.image.image_element[i].bit_size=(unsigned char) ReadBlobByte(image);
    offset++;
    dpx.image.image_element[i].packing=ReadBlobShort(image);
    offset+=2;
    dpx.image.image_element[i].encoding=ReadBlobShort(image);
    offset+=2;
    dpx.image.image_element[i].data_offset=ReadBlobLong(image);
    offset+=4;
    dpx.image.image_element[i].end_of_line_padding=ReadBlobLong(image);
    offset+=4;
    dpx.image.image_element[i].end_of_image_padding=ReadBlobLong(image);
    offset+=4;
    offset+=ReadBlob(image,sizeof(dpx.image.image_element[i].description),
      (unsigned char *) dpx.image.image_element[i].description);
  }
  (void) SetImageColorspace(image,RGBColorspace);
  offset+=ReadBlob(image,sizeof(dpx.image.reserve),(unsigned char *)
    dpx.image.reserve);
  if (dpx.file.image_offset >= 1664U)
    {
      /*
        Read DPX orientation header.
      */
      dpx.orientation.x_offset=ReadBlobLong(image);
      offset+=4;
      if (dpx.orientation.x_offset != ~0U)
        (void) FormatImageProperty(image,"dpx:orientation.x_offset","%u",
          dpx.orientation.x_offset);
      dpx.orientation.y_offset=ReadBlobLong(image);
      offset+=4;
      if (dpx.orientation.y_offset != ~0U)
        (void) FormatImageProperty(image,"dpx:orientation.y_offset","%u",
          dpx.orientation.y_offset);
      dpx.orientation.x_center=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.orientation.x_center) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:orientation.x_center","%g",
          dpx.orientation.x_center);
      dpx.orientation.y_center=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.orientation.y_center) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:orientation.y_center","%g",
          dpx.orientation.y_center);
      dpx.orientation.x_size=ReadBlobLong(image);
      offset+=4;
      if (dpx.orientation.x_size != ~0U)
        (void) FormatImageProperty(image,"dpx:orientation.x_size","%u",
          dpx.orientation.x_size);
      dpx.orientation.y_size=ReadBlobLong(image);
      offset+=4;
      if (dpx.orientation.y_size != ~0U)
        (void) FormatImageProperty(image,"dpx:orientation.y_size","%u",
          dpx.orientation.y_size);
      offset+=ReadBlob(image,sizeof(dpx.orientation.filename),(unsigned char *)
        dpx.orientation.filename);
      if (*dpx.orientation.filename != '\0')
        (void) FormatImageProperty(image,"dpx:orientation.filename","%.100s",
          dpx.orientation.filename);
      offset+=ReadBlob(image,sizeof(dpx.orientation.timestamp),(unsigned char *)
        dpx.orientation.timestamp);
      if (*dpx.orientation.timestamp != '\0')
        (void) FormatImageProperty(image,"dpx:orientation.timestamp","%.24s",
          dpx.orientation.timestamp);
      offset+=ReadBlob(image,sizeof(dpx.orientation.device),(unsigned char *)
        dpx.orientation.device);
      if (*dpx.orientation.device != '\0')
        (void) FormatImageProperty(image,"dpx:orientation.device","%.32s",
          dpx.orientation.device);
      offset+=ReadBlob(image,sizeof(dpx.orientation.serial),(unsigned char *)
        dpx.orientation.serial);
      if (*dpx.orientation.serial != '\0')
        (void) FormatImageProperty(image,"dpx:orientation.serial","%.32s",
          dpx.orientation.serial);
      for (i=0; i < 4; i++)
      {
        dpx.orientation.border[i]=ReadBlobShort(image);
        offset+=2;
      }
      if ((dpx.orientation.border[0] != (unsigned short) (~0)) &&
          (dpx.orientation.border[1] != (unsigned short) (~0)))
        (void) FormatImageProperty(image,"dpx:orientation.border","%dx%d%+d%+d",          dpx.orientation.border[0],dpx.orientation.border[1],
          dpx.orientation.border[2],dpx.orientation.border[3]);
      for (i=0; i < 2; i++)
      {
        dpx.orientation.aspect_ratio[i]=ReadBlobLong(image);
        offset+=4;
      }
      if ((dpx.orientation.aspect_ratio[0] != ~0U) &&
          (dpx.orientation.aspect_ratio[1] != ~0U))
        (void) FormatImageProperty(image,"dpx:orientation.aspect_ratio",
          "%ux%u",dpx.orientation.aspect_ratio[0],
          dpx.orientation.aspect_ratio[1]);
      offset+=ReadBlob(image,sizeof(dpx.orientation.reserve),(unsigned char *)
        dpx.orientation.reserve);
    }
  if (dpx.file.image_offset >= 1920U)
    {
      /*
        Read DPX film header.
      */
      offset+=ReadBlob(image,sizeof(dpx.film.id),(unsigned char *) dpx.film.id);
      if (*dpx.film.id != '\0')
        (void) FormatImageProperty(image,"dpx:film.id","%.2s",dpx.film.id);
      offset+=ReadBlob(image,sizeof(dpx.film.type),(unsigned char *)
        dpx.film.type);
      if (*dpx.film.type != '\0')
        (void) FormatImageProperty(image,"dpx:film.type","%.2s",dpx.film.type);
      offset+=ReadBlob(image,sizeof(dpx.film.offset),(unsigned char *)
        dpx.film.offset);
      if (*dpx.film.offset != '\0')
        (void) FormatImageProperty(image,"dpx:film.offset","%.2s",
          dpx.film.offset);
      offset+=ReadBlob(image,sizeof(dpx.film.prefix),(unsigned char *)
        dpx.film.prefix);
      if (*dpx.film.prefix != '\0')
        (void) FormatImageProperty(image,"dpx:film.prefix","%.6s",
          dpx.film.prefix);
      offset+=ReadBlob(image,sizeof(dpx.film.count),(unsigned char *)
        dpx.film.count);
      if (*dpx.film.count != '\0')
        (void) FormatImageProperty(image,"dpx:film.count","%.4s",
          dpx.film.count);
      offset+=ReadBlob(image,sizeof(dpx.film.format),(unsigned char *)
        dpx.film.format);
      if (*dpx.film.format != '\0')
        (void) FormatImageProperty(image,"dpx:film.format","%.4s",
          dpx.film.format);
      dpx.film.frame_position=ReadBlobLong(image);
      offset+=4;
      if (dpx.film.frame_position != ~0U)
        (void) FormatImageProperty(image,"dpx:film.frame_position","%u",
          dpx.film.frame_position);
      dpx.film.sequence_extent=ReadBlobLong(image);
      offset+=4;
      if (dpx.film.sequence_extent != ~0U)
        (void) FormatImageProperty(image,"dpx:film.sequence_extent","%u",
          dpx.film.sequence_extent);
      dpx.film.held_count=ReadBlobLong(image);
      offset+=4;
      if (dpx.film.held_count != ~0U)
        (void) FormatImageProperty(image,"dpx:film.held_count","%u",
          dpx.film.held_count);
      dpx.film.frame_rate=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.film.frame_rate) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:film.frame_rate","%g",
          dpx.film.frame_rate);
      dpx.film.shutter_angle=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.film.shutter_angle) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:film.shutter_angle","%g",
          dpx.film.shutter_angle);
      offset+=ReadBlob(image,sizeof(dpx.film.frame_id),(unsigned char *)
        dpx.film.frame_id);
      if (*dpx.film.frame_id != '\0')
        (void) FormatImageProperty(image,"dpx:film.frame_id","%.32s",
          dpx.film.frame_id);
      offset+=ReadBlob(image,sizeof(dpx.film.slate),(unsigned char *)
        dpx.film.slate);
      if (*dpx.film.slate != '\0')
        (void) FormatImageProperty(image,"dpx:film.slate","%.100s",
          dpx.film.slate);
      offset+=ReadBlob(image,sizeof(dpx.film.reserve),(unsigned char *)
        dpx.film.reserve);
    }
  if (dpx.file.image_offset >= 2048U)
    {
      /*
        Read DPX television header.
      */
      dpx.television.time_code=(unsigned int) ReadBlobLong(image);
      offset+=4;
      TimeCodeToString(dpx.television.time_code,value);
      (void) SetImageProperty(image,"dpx:television.time.code",value);
      dpx.television.user_bits=(unsigned int) ReadBlobLong(image);
      offset+=4;
      TimeCodeToString(dpx.television.user_bits,value);
      (void) SetImageProperty(image,"dpx:television.user.bits",value);
      dpx.television.interlace=(unsigned char) ReadBlobByte(image);
      offset++;
      if (dpx.television.interlace != 0)
        (void) FormatImageProperty(image,"dpx:television.interlace","%.20g",
          (double) dpx.television.interlace);
      dpx.television.field_number=(unsigned char) ReadBlobByte(image);
      offset++;
      if (dpx.television.field_number != 0)
        (void) FormatImageProperty(image,"dpx:television.field_number","%.20g",
          (double) dpx.television.field_number);
      dpx.television.video_signal=(unsigned char) ReadBlobByte(image);
      offset++;
      if (dpx.television.video_signal != 0)
        (void) FormatImageProperty(image,"dpx:television.video_signal","%.20g",
          (double) dpx.television.video_signal);
      dpx.television.padding=(unsigned char) ReadBlobByte(image);
      offset++;
      if (dpx.television.padding != 0)
        (void) FormatImageProperty(image,"dpx:television.padding","%d",
          dpx.television.padding);
      dpx.television.horizontal_sample_rate=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.horizontal_sample_rate) != MagickFalse)
        (void) FormatImageProperty(image,
          "dpx:television.horizontal_sample_rate","%g",
          dpx.television.horizontal_sample_rate);
      dpx.television.vertical_sample_rate=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.vertical_sample_rate) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.vertical_sample_rate",
          "%g",dpx.television.vertical_sample_rate);
      dpx.television.frame_rate=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.frame_rate) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.frame_rate","%g",
          dpx.television.frame_rate);
      dpx.television.time_offset=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.time_offset) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.time_offset","%g",
          dpx.television.time_offset);
      dpx.television.gamma=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.gamma) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.gamma","%g",
          dpx.television.gamma);
      dpx.television.black_level=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.black_level) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.black_level","%g",
          dpx.television.black_level);
      dpx.television.black_gain=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.black_gain) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.black_gain","%g",
          dpx.television.black_gain);
      dpx.television.break_point=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.break_point) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.break_point","%g",
          dpx.television.break_point);
      dpx.television.white_level=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.white_level) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.white_level","%g",
          dpx.television.white_level);
      dpx.television.integration_times=ReadBlobFloat(image);
      offset+=4;
      if (IsFloatDefined(dpx.television.integration_times) != MagickFalse)
        (void) FormatImageProperty(image,"dpx:television.integration_times",
          "%g",dpx.television.integration_times);
      offset+=ReadBlob(image,sizeof(dpx.television.reserve),(unsigned char *)
        dpx.television.reserve);
    }
  if (dpx.file.image_offset > 2080U)
    {
      /*
        Read DPX user header.
      */
      offset+=ReadBlob(image,sizeof(dpx.user.id),(unsigned char *) dpx.user.id);
      if (*dpx.user.id != '\0')
        (void) FormatImageProperty(image,"dpx:user.id","%.32s",dpx.user.id);
      if ((dpx.file.user_size != ~0U) &&
          ((size_t) dpx.file.user_size > sizeof(dpx.user.id)))
        {
          StringInfo
            *profile;

           profile=BlobToStringInfo((const void *) NULL,
             dpx.file.user_size-sizeof(dpx.user.id));
           if (profile == (StringInfo *) NULL)
             ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
           offset+=ReadBlob(image,GetStringInfoLength(profile),
             GetStringInfoDatum(profile));
           (void) SetImageProfile(image,"dpx:user-data",profile);
           profile=DestroyStringInfo(profile);
        }
    }
  for ( ; offset < (MagickOffsetType) dpx.file.image_offset; offset++)
    (void) ReadBlobByte(image);
  /*
    Read DPX image header.
  */
  if (image_info->ping != MagickFalse)
    {
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
   for (n=0; n < (ssize_t) dpx.image.number_elements; n++)
   {
     /*
      Convert DPX raster image to pixel packets.
    */
    if ((dpx.image.image_element[n].data_offset != ~0U) &&
        (dpx.image.image_element[n].data_offset != 0U))
      {
         MagickOffsetType
           data_offset;

         data_offset=(MagickOffsetType) dpx.image.image_element[n].data_offset;
         if (data_offset < offset)
           offset=SeekBlob(image,data_offset,SEEK_SET);
         else
           for ( ; offset < data_offset; offset++)
             (void) ReadBlobByte(image);
          if (offset != data_offset)
            ThrowReaderException(CorruptImageError,"UnableToReadImageData");
       }
    SetPrimaryChromaticity((DPXColorimetric)
      dpx.image.image_element[n].colorimetric,&image->chromaticity);
    image->depth=dpx.image.image_element[n].bit_size;
    samples_per_pixel=1;
    quantum_type=GrayQuantum;
    component_type=dpx.image.image_element[n].descriptor;
    switch (component_type)
    {
      case CbYCrY422ComponentType:
      {
        samples_per_pixel=2;
        quantum_type=CbYCrYQuantum;
        break;
      }
      case CbYACrYA4224ComponentType:
      case CbYCr444ComponentType:
      {
        samples_per_pixel=3;
        quantum_type=CbYCrQuantum;
        break;
      }
      case RGBComponentType:
      {
        samples_per_pixel=3;
        quantum_type=RGBQuantum;
        break;
      }
      case ABGRComponentType:
      case RGBAComponentType:
      {
        image->matte=MagickTrue;
        samples_per_pixel=4;
        quantum_type=RGBAQuantum;
        break;
      }
      default:
        break;
    }
    switch (component_type)
    {
      case CbYCrY422ComponentType:
      case CbYACrYA4224ComponentType:
      case CbYCr444ComponentType:
      {
        (void) SetImageColorspace(image,Rec709YCbCrColorspace);
        break;
      }
      case LumaComponentType:
      {
        (void) SetImageColorspace(image,GRAYColorspace);
        break;
      }
      default:
      {
        (void) SetImageColorspace(image,RGBColorspace);
        if (dpx.image.image_element[n].transfer_characteristic == LogarithmicColorimetric)
          (void) SetImageColorspace(image,LogColorspace);
        if (dpx.image.image_element[n].transfer_characteristic == PrintingDensityColorimetric)
          (void) SetImageColorspace(image,LogColorspace);
        break;
      }
    }
    extent=GetBytesPerRow(image->columns,samples_per_pixel,image->depth,
      dpx.image.image_element[n].packing == 0 ? MagickFalse : MagickTrue);
    /*
      DPX any-bit pixel format.
    */
    status=MagickTrue;
    row=0;
    quantum_info=AcquireQuantumInfo(image_info,image);
    if (quantum_info == (QuantumInfo *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    SetQuantumQuantum(quantum_info,32);
    SetQuantumPack(quantum_info,dpx.image.image_element[n].packing == 0 ?
      MagickTrue : MagickFalse);
    for (y=0; y < (ssize_t) image->rows; y++)
    {
      MagickBooleanType
        sync;

      register PixelPacket
        *q;

      size_t
        length;

      ssize_t
        count,
        offset;

      unsigned char
        *pixels;

      if (status == MagickFalse)
        continue;
      pixels=GetQuantumPixels(quantum_info);
      {
        count=ReadBlob(image,extent,pixels);
        if ((image->progress_monitor != (MagickProgressMonitor) NULL) &&
            (image->previous == (Image *) NULL))
          {
            MagickBooleanType
              proceed;

            proceed=SetImageProgress(image,LoadImageTag,(MagickOffsetType) row,
              image->rows);
            if (proceed == MagickFalse)
              status=MagickFalse;
          }
        offset=row++;
      }
      if (count != (ssize_t) extent)
        status=MagickFalse;
      q=QueueAuthenticPixels(image,0,offset,image->columns,1,exception);
      if (q == (PixelPacket *) NULL)
        {
          status=MagickFalse;
          continue;
        }
      length=ImportQuantumPixels(image,(CacheView *) NULL,quantum_info,
        quantum_type,pixels,exception);
      (void) length;
      sync=SyncAuthenticPixels(image,exception);
      if (sync == MagickFalse)
        status=MagickFalse;
    }
    quantum_info=DestroyQuantumInfo(quantum_info);
    if (status == MagickFalse)
      ThrowReaderException(CorruptImageError,"UnableToReadImageData");
    SetQuantumImageType(image,quantum_type);
    if (EOFBlob(image) != MagickFalse)
      ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
        image->filename);
  }
  (void) CloseBlob(image);
  return(GetFirstImageInList(image));
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **84**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `ChangeLog` | modified | 2 | 0 |
| `coders/aai.c` | modified | 6 | 0 |
| `coders/art.c` | modified | 6 | 0 |
| `coders/avs.c` | modified | 6 | 0 |
| `coders/bgr.c` | modified | 6 | 0 |
| `coders/bmp.c` | modified | 6 | 0 |
| `coders/cin.c` | modified | 7 | 1 |
| `coders/clipboard.c` | modified | 8 | 2 |
| `coders/cmyk.c` | modified | 6 | 0 |
| `coders/cut.c` | modified | 7 | 1 |
| `coders/dcm.c` | modified | 6 | 0 |
| `coders/dds.c` | modified | 6 | 0 |
| `coders/dib.c` | modified | 7 | 1 |
| `coders/djvu.c` | modified | 8 | 1 |
| `coders/dps.c` | modified | 6 | 0 |
| `coders/dpx.c` **(funcao marcada esta aqui)** | modified | 6 | 0 |
| `coders/emf.c` | modified | 6 | 0 |
| `coders/exr.c` | modified | 6 | 0 |
| `coders/fax.c` | modified | 6 | 0 |
| `coders/fits.c` | modified | 6 | 0 |
| `coders/fpx.c` | modified | 6 | 0 |
| `coders/gif.c` | modified | 6 | 0 |
| `coders/gray.c` | modified | 6 | 0 |
| `coders/hald.c` | modified | 7 | 2 |
| `coders/hdr.c` | modified | 6 | 0 |
| `coders/hrz.c` | modified | 6 | 0 |
| `coders/icon.c` | modified | 6 | 0 |
| `coders/ipl.c` | modified | 7 | 1 |
| `coders/jbig.c` | modified | 6 | 0 |
| `coders/jp2.c` | modified | 6 | 0 |
| `coders/jpeg.c` | modified | 6 | 0 |
| `coders/label.c` | modified | 6 | 0 |
| `coders/mac.c` | modified | 6 | 0 |
| `coders/map.c` | modified | 6 | 0 |
| `coders/mat.c` | modified | 6 | 0 |
| `coders/miff.c` | modified | 6 | 0 |
| `coders/mono.c` | modified | 6 | 0 |
| `coders/mpc.c` | modified | 6 | 0 |
| `coders/mtv.c` | modified | 6 | 0 |
| `coders/mvg.c` | modified | 6 | 0 |
| `coders/null.c` | modified | 9 | 0 |
| `coders/otb.c` | modified | 6 | 0 |
| `coders/palm.c` | modified | 6 | 0 |
| `coders/pango.c` | modified | 8 | 2 |
| `coders/pcd.c` | modified | 6 | 0 |
| `coders/pcx.c` | modified | 6 | 0 |
| `coders/pdb.c` | modified | 6 | 0 |
| `coders/pict.c` | modified | 6 | 0 |
| `coders/pix.c` | modified | 6 | 0 |
| `coders/psd.c` | modified | 6 | 0 |
| `coders/raw.c` | modified | 6 | 0 |
| `coders/rgb.c` | modified | 6 | 0 |
| `coders/rgf.c` | modified | 6 | 2 |
| `coders/rla.c` | modified | 6 | 0 |
| `coders/rle.c` | modified | 6 | 0 |
| `coders/scr.c` | modified | 6 | 0 |
| `coders/screenshot.c` | modified | 9 | 1 |
| `coders/sct.c` | modified | 6 | 0 |
| `coders/sgi.c` | modified | 6 | 0 |
| `coders/sixel.c` | modified | 6 | 1 |
| `coders/stegano.c` | modified | 6 | 0 |
| `coders/sun.c` | modified | 6 | 0 |
| `coders/svg.c` | modified | 6 | 0 |
| `coders/tga.c` | modified | 6 | 0 |
| `coders/tiff.c` | modified | 6 | 0 |
| `coders/tile.c` | modified | 9 | 0 |
| `coders/tim.c` | modified | 6 | 0 |
| `coders/ttf.c` | modified | 6 | 0 |
| `coders/txt.c` | modified | 12 | 0 |
| `coders/uyvy.c` | modified | 6 | 0 |
| `coders/vicar.c` | modified | 6 | 0 |
| `coders/viff.c` | modified | 6 | 0 |
| `coders/vips.c` | modified | 6 | 0 |
| `coders/wbmp.c` | modified | 6 | 0 |
| `coders/webp.c` | modified | 6 | 0 |
| `coders/wmf.c` | modified | 9 | 0 |
| `coders/wpg.c` | modified | 6 | 0 |
| `coders/xbm.c` | modified | 6 | 0 |
| `coders/xc.c` | modified | 6 | 0 |
| `coders/xcf.c` | modified | 6 | 0 |
| `coders/xpm.c` | modified | 6 | 0 |
| `coders/xwd.c` | modified | 6 | 0 |
| `coders/ycbcr.c` | modified | 12 | 0 |
| `coders/yuv.c` | modified | 12 | 0 |


### `coders/dpx.c`

```diff
@@ -1126,6 +1126,12 @@ static Image *ReadDPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   for (n=0; n < (ssize_t) dpx.image.number_elements; n++)
   {
     /*
```


### `ChangeLog`

```diff
@@ -22,6 +22,8 @@
     Mateusz Jurczyk of the Google Security Team).
   * Additional PNM sanity checks (reference
     [url removida]
+  * The SetImageBias() biad value is no longer ignored (reference
+    [url removida]
 
 2014-11-16  6.9.0-0 Cristy  <quetzlzacatenango@image...>
   * New version 6.9.0-0, SVN revision 17067.
```


### `coders/aai.c`

```diff
@@ -158,6 +158,12 @@ static Image *ReadAAIImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     pixels=(unsigned char *) AcquireQuantumMemory(image->columns,
       4*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
```


### `coders/art.c`

```diff
@@ -155,6 +155,12 @@ static Image *ReadARTImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/avs.c`

```diff
@@ -160,6 +160,12 @@ static Image *ReadAVSImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     pixels=(unsigned char *) AcquireQuantumMemory(image->columns,
       4*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
```


### `coders/bgr.c`

```diff
@@ -197,6 +197,12 @@ static Image *ReadBGRImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     switch (image_info->interlace)
     {
       case NoInterlace:
```


### `coders/bmp.c`

```diff
@@ -928,6 +928,12 @@ static Image *ReadBMPImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Read image data.
     */
```


### `coders/cin.c`

```diff
@@ -721,11 +721,17 @@ static Image *ReadCINImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->depth=cin.image.channel[0].bits_per_pixel;
   image->columns=cin.image.channel[0].pixels_per_line;
   image->rows=cin.image.channel[0].lines_per_image;
-  if (image_info->ping)
+  if (image_info->ping != MagickFalse)
     {
       (void) CloseBlob(image);
       return(image);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert CIN raster image to pixel packets.
   */
```


### `coders/clipboard.c`

```diff
@@ -136,7 +136,7 @@ static Image *ReadCLIPBOARDImage(const ImageInfo *image_info,
     bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
     hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
     CloseClipboard();
-    if ( bitmapH == NULL )
+    if (bitmapH == NULL)
       ThrowReaderException(CoderError,"NoBitmapOnClipboard");
     {
       BITMAPINFO
@@ -163,8 +163,14 @@ static Image *ReadCLIPBOARDImage(const ImageInfo *image_info,
       GetObject(bitmapH,sizeof(BITMAP),(LPSTR) &bitmap);
       if ((image->columns == 0) || (image->rows == 0))
         {
-          image->rows=bitmap.bmHeight;
           image->columns=bitmap.bmWidth;
+          image->rows=bitmap.bmHeight;
+        }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
         }
       /*
         Initialize the bitmap header info.
```


### `coders/cmyk.c`

```diff
@@ -197,6 +197,12 @@ static Image *ReadCMYKImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,CMYKColorspace);
     switch (image_info->interlace)
     {
```


### `coders/cut.c`

```diff
@@ -371,7 +371,13 @@ static Image *ReadCUTImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->depth=8;
   image->colors=(size_t) (GetQuantumRange(1UL*i)+1);
 
-  if (image_info->ping) goto Finish;
+  if (image_info->ping != MagickFalse) goto Finish;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
 
   /* ----- Do something with palette ----- */
   if ((clone_info=CloneImageInfo(image_info)) == NULL) goto NoPalette;
```


### `coders/dcm.c`

```diff
@@ -3689,6 +3689,12 @@ static Image *ReadDCMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns=(size_t) width;
     image->rows=(size_t) height;
     image->depth=depth;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        break;
+      }
     image->colorspace=RGBColorspace;
     if ((image->colormap == (PixelPacket *) NULL) && (samples_per_pixel == 1))
       {
```


### `coders/dds.c`

```diff
@@ -1834,6 +1834,12 @@ static Image *ReadDDSImage(const ImageInfo *image_info,ExceptionInfo *exception)
         (void) CloseBlob(image);
         return(GetFirstImageInList(image));
       }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 
     if ((decoder)(image, &dds_info, exception) != MagickTrue)
       {
```


### `coders/dib.c`

```diff
@@ -520,7 +520,7 @@ static Image *ReadDIBImage(const ImageInfo *image_info,ExceptionInfo *exception)
   */
   (void) ResetMagickMemory(&dib_info,0,sizeof(dib_info));
   dib_info.size=ReadBlobLSBLong(image);
-  if (dib_info.size!=40)
+  if (dib_info.size != 40)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   /*
     Microsoft Windows 3.X DIB image file.
@@ -573,6 +573,12 @@ static Image *ReadDIBImage(const ImageInfo *image_info,ExceptionInfo *exception)
         if ((geometry.height != 0) && (geometry.height < image->rows))
           image->rows=geometry.height;
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image->storage_class == PseudoClass)
     {
       size_t
```


### `coders/djvu.c`

```diff
@@ -418,7 +418,7 @@ get_page_image(LoadContext *lc, ddjvu_page_t *page, int x, int y, int w, int h,
                                 if (SyncAuthenticPixels(image,&image->exception) == MagickFalse)
                                         break;
                         }
-                if (!image->ping)
+                if (image->ping == MagickFalse)
                   SyncImage(image);
         } else {
 #if DEBUG
@@ -577,6 +577,7 @@ static Image *ReadOneDJVUImage(LoadContext* lc,const int pagenum,
   Image *image;
   int logging;
   int tag;
+  MagickBooleanType status;
 
         /* so, we know that the page is there! Get its dimension, and  */
 
@@ -667,6 +668,12 @@ static Image *ReadOneDJVUImage(LoadContext* lc,const int pagenum,
                 image->matte = MagickTrue;
                 /* is this useful? */
         }
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
 #if DEBUG
         printf("now filling %.20g x %.20g\n",(double) image->columns,(double)
           image->rows);
```


### `coders/dps.c`

```diff
@@ -328,6 +328,12 @@ static Image *ReadDPSImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   switch (image->storage_class)
   {
     case DirectClass:
```


### `coders/emf.c`

```diff
@@ -507,6 +507,12 @@ static Image *ReadEMFImage(const ImageInfo *image_info,
       y=0;
       (void) GetGeometry(image_info->size,&x,&y,&image->columns,&image->rows);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image_info->page != (char *) NULL)
     {
       char
```


### `coders/exr.c`

```diff
@@ -212,6 +212,12 @@ static Image *ReadEXRImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   scanline=(ImfRgba *) AcquireQuantumMemory(image->columns,sizeof(*scanline));
   if (scanline == (ImfRgba *) NULL)
     {
```


### `coders/fax.c`

```diff
@@ -178,6 +178,12 @@ static Image *ReadFAXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   status=HuffmanDecodeImage(image);
   if (status == MagickFalse)
     ThrowReaderException(CorruptImageError,"UnableToReadImageData");
```


### `coders/fits.c`

```diff
@@ -423,6 +423,12 @@ static Image *ReadFITSImage(const ImageInfo *image_info,
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
       Initialize image structure.
     */
```


### `coders/fpx.c`

```diff
@@ -352,6 +352,12 @@ static Image *ReadFPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       FPX_ClearSystem();
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Allocate memory for the image and pixel buffer.
   */
```


### `coders/gif.c`

```diff
@@ -1350,6 +1350,12 @@ static Image *ReadGIFImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Decode image.
     */
```


### `coders/gray.c`

```diff
@@ -187,6 +187,12 @@ static Image *ReadGRAYImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,GRAYColorspace);
     if (scene == 0)
       {
```


### `coders/hald.c`

```diff
@@ -125,6 +125,12 @@ static Image *ReadHALDImage(const ImageInfo *image_info,
   cube_size=level*level;
   image->columns=(size_t) (level*cube_size);
   image->rows=(size_t) (level*cube_size);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   for (y=0; y < (ssize_t) image->rows; y+=(ssize_t) level)
   {
     ssize_t
@@ -137,8 +143,7 @@ static Image *ReadHALDImage(const ImageInfo *image_info,
 
     if (status == MagickFalse)
       continue;
-    q=QueueAuthenticPixels(image,0,y,image->columns,(size_t) level,
-      exception);
+    q=QueueAuthenticPixels(image,0,y,image->columns,(size_t) level,exception);
     if (q == (PixelPacket *) NULL)
       {
         status=MagickFalse;
```


### `coders/hdr.c`

```diff
@@ -382,6 +382,12 @@ static Image *ReadHDRImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read RGBE (red+green+blue+exponent) pixels.
   */
```


### `coders/hrz.c`

```diff
@@ -142,6 +142,12 @@ static Image *ReadHRZImage(const ImageInfo *image_info,ExceptionInfo *exception)
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


### `coders/icon.c`

```diff
@@ -462,6 +462,12 @@ static Image *ReadICONImage(const ImageInfo *image_info,
             (image_info->number_scenes != 0))
           if (image->scene >= (image_info->scene+image_info->number_scenes-1))
             break;
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
         bytes_per_line=(((image->columns*icon_info.bits_per_pixel)+31) &
           ~31) >> 3;
         (void) bytes_per_line;
```


### `coders/ipl.c`

```diff
@@ -315,9 +315,15 @@ static Image *ReadIPLImage(const ImageInfo *image_info,ExceptionInfo *exception)
   {
     SetHeaderFromIPL(image, &ipl_info);
 
-  if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
+    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 /*
    printf("Length: %.20g, Memory size: %.20g\n", (double) length,(double)
      image->depth);
```


### `coders/jbig.c`

```diff
@@ -219,6 +219,12 @@ static Image *ReadJBIGImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert X bitmap image to pixel packets.
   */
```


### `coders/jp2.c`

```diff
@@ -398,6 +398,12 @@ static Image *ReadJP2Image(const ImageInfo *image_info,ExceptionInfo *exception)
   image->columns=(size_t) jp2_image->comps[0].w;
   image->rows=(size_t) jp2_image->comps[0].h;
   image->depth=jp2_image->comps[0].prec;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->compression=JPEG2000Compression;
   if (jp2_image->numcomps <= 2)
     {
```


### `coders/jpeg.c`

```diff
@@ -1263,6 +1263,12 @@ static Image *ReadJPEGImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   memory_info=AcquireVirtualMemory((size_t) image->columns,
     jpeg_info.output_components*sizeof(*jpeg_pixels));
   if (memory_info == (MemoryInfo *) NULL)
```


### `coders/label.c`

```diff
@@ -213,6 +213,12 @@ static Image *ReadLABELImage(const ImageInfo *image_info,
       draw_info->stroke_width+0.5);
   if (image->rows == 0)
     image->rows=(size_t) (draw_info->pointsize+draw_info->stroke_width+0.5);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (draw_info->gravity == UndefinedGravity)
     {
       (void) FormatLocaleString(geometry,MaxTextExtent,"%+g%+g",
```


### `coders/mac.c`

```diff
@@ -156,6 +156,12 @@ static Image *ReadMACImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert MAC raster image to pixel packets.
   */
```


### `coders/map.c`

```diff
@@ -206,6 +206,12 @@ static Image *ReadMAPImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read image pixels.
   */
```


### `coders/mat.c`

```diff
@@ -874,6 +874,12 @@ RestoreMSCWarning
       image->rows = temp;
       goto done_reading; /* !!!!!! BAD  !!!! */
     }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 
   /* ----- Load raster data ----- */
     BImgBuff = (unsigned char *) AcquireQuantumMemory((size_t) (ldblk),sizeof(unsigned char));    /* Ldblk was set in the check phase */
```


### `coders/miff.c`

```diff
@@ -1246,6 +1246,12 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
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


### `coders/mono.c`

```diff
@@ -154,6 +154,12 @@ static Image *ReadMONOImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/mpc.c`

```diff
@@ -929,6 +929,12 @@ static Image *ReadMPCImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Attach persistent pixel cache.
     */
```


### `coders/mtv.c`

```diff
@@ -158,6 +158,12 @@ static Image *ReadMTVImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Convert MTV raster image to pixel packets.
     */
```


### `coders/mvg.c`

```diff
@@ -190,6 +190,12 @@ static Image *ReadMVGImage(const ImageInfo *image_info,ExceptionInfo *exception)
     DefaultResolution;
   image->columns=(size_t) (draw_info->affine.sx*image->columns);
   image->rows=(size_t) (draw_info->affine.sy*image->rows);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (SetImageBackgroundColor(image) == MagickFalse)
     {
       InheritException(exception,&image->exception);
```


### `coders/null.c`

```diff
@@ -99,6 +99,9 @@ static Image *ReadNULLImage(const ImageInfo *image_info,
   Image
     *image;
 
+  MagickBooleanType
+    status;
+
   MagickPixelPacket
     background;
 
@@ -129,6 +132,12 @@ static Image *ReadNULLImage(const ImageInfo *image_info,
     image->columns=1;
   if (image->rows == 0)
     image->rows=1;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->matte=MagickTrue;
   GetMagickPixelPacket(image,&background);
   background.opacity=(MagickRealType) TransparentOpacity;
```


### `coders/otb.c`

```diff
@@ -168,6 +168,12 @@ static Image *ReadOTBImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/palm.c`

```diff
@@ -329,6 +329,12 @@ static Image *ReadPALMImage(const ImageInfo *image_info,
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     if ((image->columns == 0) || (image->rows == 0))
       ThrowReaderException(CorruptImageError,"NegativeOrZeroImageSize");
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     bytes_per_row=ReadBlobMSBShort(image);
     flags=ReadBlobMSBShort(image);
     bits_per_pixel=(size_t) ReadBlobByte(image);
```


### `coders/pango.c`

```diff
@@ -375,11 +375,17 @@ static Image *ReadPANGOImage(const ImageInfo *image_info,
         (image->y_resolution == 0.0 ? 90.0 : image->y_resolution)+45.0)/90.0+
         0.5));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Render markup.
   */
-  stride=(size_t) cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32,
-    (int) image->columns);
+  stride=(size_t) cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32,(int)
+    image->columns);
   pixel_info=AcquireVirtualMemory(image->rows,stride*sizeof(*pixels));
   if (pixel_info == (MemoryInfo *) NULL)
     {
```


### `coders/pcd.c`

```diff
@@ -594,6 +594,12 @@ static Image *ReadPCDImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns<<=1;
     image->rows<<=1;
   }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Allocate luma and chroma memory.
   */
```


### `coders/pcx.c`

```diff
@@ -395,6 +395,12 @@ static Image *ReadPCXImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Read image data.
     */
```


### `coders/pdb.c`

```diff
@@ -402,6 +402,12 @@ static Image *ReadPDBImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   packets=(bits_per_pixel*image->columns+7)/8;
   pixels=(unsigned char *) AcquireQuantumMemory(packets+256UL,image->rows*
     sizeof(*pixels));
```


### `coders/pict.c`

```diff
@@ -922,6 +922,12 @@ static Image *ReadPICTImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if ((version == 1) || ((TellBlob(image) % 2) != 0))
       code=ReadBlobByte(image);
     if (version == 2)
```


### `coders/pix.c`

```diff
@@ -161,6 +161,12 @@ static Image *ReadPIXImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Convert PIX raster image to pixel packets.
     */
```


### `coders/psd.c`

```diff
@@ -1653,6 +1653,12 @@ static Image *ReadPSDImage(const ImageInfo *image_info,
   image->depth=psd_info.depth;
   image->columns=psd_info.columns;
   image->rows=psd_info.rows;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (SetImageBackgroundColor(image) == MagickFalse)
     {
       InheritException(exception,&image->exception);
```


### `coders/raw.c`

```diff
@@ -180,6 +180,12 @@ static Image *ReadRAWImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (scene == 0)
       {
         length=GetQuantumExtent(canvas_image,quantum_info,quantum_type);
```


### `coders/rgb.c`

```diff
@@ -201,6 +201,12 @@ static Image *ReadRGBImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     switch (image_info->interlace)
     {
       case NoInterlace:
```


### `coders/rgf.c`

```diff
@@ -172,8 +172,12 @@ static Image *ReadRGFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
-
-
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read hex image data.
   */
```


### `coders/rla.c`

```diff
@@ -261,6 +261,12 @@ static Image *ReadRLAImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   scanlines=(ssize_t *) AcquireQuantumMemory(image->rows,sizeof(*scanlines));
   if (scanlines == (ssize_t *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```


### `coders/rle.c`

```diff
@@ -293,6 +293,12 @@ static Image *ReadRLEImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Allocate RLE pixels.
     */
```


### `coders/scr.c`

```diff
@@ -156,6 +156,12 @@ static Image *ReadSCRImage(const ImageInfo *image_info,ExceptionInfo *exception)
     }
   image->columns = 256;
   image->rows = 192;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   count=ReadBlob(image,6144,(unsigned char *) zxscr);
   (void) count;
   count=ReadBlob(image,768,(unsigned char *) zxattr);
```


### `coders/screenshot.c`

```diff
@@ -133,6 +133,9 @@ static Image *ReadSCREENSHOTImage(const ImageInfo *image_info,
     int
       i;
 
+    MagickBooleanType
+      status;
+
     register PixelPacket
       *q;
 
@@ -162,7 +165,12 @@ static Image *ReadSCREENSHOTImage(const ImageInfo *image_info,
       screen->columns=(size_t) GetDeviceCaps(hDC,HORZRES);
       screen->rows=(size_t) GetDeviceCaps(hDC,VERTRES);
       screen->storage_class=DirectClass;
-
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       if (image == (Image *) NULL)
         image=screen;
       else
```


### `coders/sct.c`

```diff
@@ -224,6 +224,12 @@ static Image *ReadSCTImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert SCT raster image to pixel packets.
   */
```


### `coders/sgi.c`

```diff
@@ -374,6 +374,12 @@ static Image *ReadSGIImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse)  && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Allocate SGI pixels.
     */
```


### `coders/sixel.c`

```diff
@@ -1027,7 +1027,12 @@ static Image *ReadSIXELImage(const ImageInfo *image_info,ExceptionInfo *exceptio
   sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
   image->depth=24;
   image->storage_class=PseudoClass;
-
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (AcquireImageColormap(image,image->colors) == MagickFalse)
     {
       sixel_pixels=(unsigned char *) RelinquishMagickMemory(sixel_pixels);
```


### `coders/stegano.c`

```diff
@@ -169,6 +169,12 @@ static Image *ReadSTEGANOImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Get hidden watermark from low-order bits of image.
   */
```


### `coders/sun.c`

```diff
@@ -412,6 +412,12 @@ static Image *ReadSUNImage(const ImageInfo *image_info,ExceptionInfo *exception)
         (void) CloseBlob(image);
         return(GetFirstImageInList(image));
       }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if ((sun_info.length*sizeof(*sun_data))/sizeof(*sun_data) !=
         sun_info.length || !sun_info.length)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```


### `coders/svg.c`

```diff
@@ -2945,6 +2945,12 @@ static Image *ReadSVGImage(const ImageInfo *image_info,ExceptionInfo *exception)
         image->columns=gdk_pixbuf_get_width(pixel_buffer);
         image->rows=gdk_pixbuf_get_height(pixel_buffer);
 #endif
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
         image->matte=MagickTrue;
         SetImageProperty(image,"svg:base-uri",
           rsvg_handle_get_base_uri(svg_handle));
```


### `coders/tga.c`

```diff
@@ -307,6 +307,12 @@ static Image *ReadTGAImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(image);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   (void) ResetMagickMemory(&pixel,0,sizeof(pixel));
   pixel.opacity=(Quantum) OpaqueOpacity;
   if (tga_info.colormap_type != 0)
```


### `coders/tiff.c`

```diff
@@ -1195,6 +1195,12 @@ RestoreMSCWarning
     image->columns=(size_t) width;
     image->rows=(size_t) height;
     image->depth=(size_t) bits_per_sample;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (image->debug != MagickFalse)
       (void) LogMagickEvent(CoderEvent,GetMagickModule(),"Image depth: %.20g",
         (double) image->depth);
```


### `coders/tile.c`

```diff
@@ -95,6 +95,9 @@ static Image *ReadTILEImage(const ImageInfo *image_info,
   ImageInfo
     *read_info;
 
+  MagickBooleanType
+    status;
+
   /*
     Initialize Image structure.
   */
@@ -115,6 +118,12 @@ static Image *ReadTILEImage(const ImageInfo *image_info,
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (*image_info->filename == '\0')
     ThrowReaderException(OptionError,"MustSpecifyAnImageName");
   image->colorspace=tile_image->colorspace;
```


### `coders/tim.c`

```diff
@@ -223,6 +223,12 @@ static Image *ReadTIMImage(const ImageInfo *image_info,ExceptionInfo *exception)
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
       Read image data.
     */
```


### `coders/ttf.c`

```diff
@@ -225,6 +225,12 @@ static Image *ReadTTFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       image=DestroyImageList(image);
       return((Image *) NULL);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Color canvas with background color
   */
```


### `coders/txt.c`

```diff
@@ -228,6 +228,12 @@ static Image *ReadTEXTImage(const ImageInfo *image_info,Image *image,
     delta.x)+0.5);
   image->rows=(size_t) floor((((double) page.height*image->y_resolution)/
     delta.y)+0.5);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->page.x=0;
   image->page.y=0;
   texture=(Image *) NULL;
@@ -437,6 +443,12 @@ static Image *ReadTXTImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->rows=height;
     for (depth=1; (GetQuantumRange(depth)+1) < max_value; depth++) ;
     image->depth=depth;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     LocaleLower(colorspace);
     i=(ssize_t) strlen(colorspace)-1;
     image->matte=MagickFalse;
```


### `coders/uyvy.c`

```diff
@@ -145,6 +145,12 @@ static Image *ReadUYVYImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Accumulate UYVY, then unpack into two pixels.
   */
```


### `coders/vicar.c`

```diff
@@ -285,6 +285,12 @@ static Image *ReadVICARImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read VICAR pixels.
   */
```


### `coders/viff.c`

```diff
@@ -478,6 +478,12 @@ static Image *ReadVIFFImage(const ImageInfo *image_info,
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
       Allocate VIFF pixels.
     */
```


### `coders/vips.c`

```diff
@@ -416,6 +416,12 @@ static Image *ReadVIPSImage(const ImageInfo *image_info,
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   image->columns=(size_t) ReadBlobLong(image);
   image->rows=(size_t) ReadBlobLong(image);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   channels=ReadBlobLong(image);
   (void) ReadBlobLong(image); /* Legacy */
   format=(VIPSBandFormat) ReadBlobLong(image);
```


### `coders/wbmp.c`

```diff
@@ -185,6 +185,12 @@ static Image *ReadWBMPImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/webp.c`

```diff
@@ -286,6 +286,12 @@ static Image *ReadWEBPImage(const ImageInfo *image_info,
           (void) CloseBlob(image);
           return(GetFirstImageInList(image));
         }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       webp_status=WebPDecode(stream,length,&configure);
     }
   if (webp_status != VP8_STATUS_OK)
```


### `coders/wmf.c`

```diff
@@ -2584,6 +2584,9 @@ static Image *ReadWMFImage(const ImageInfo *image_info,ExceptionInfo *exception)
   Image
     *image;
 
+  MagickBooleanType
+    status;
+
   unsigned long
     wmf_options_flags = 0;
 
@@ -2875,6 +2878,12 @@ static Image *ReadWMFImage(const ImageInfo *image_info,ExceptionInfo *exception)
           "leave ReadWMFImage()");
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(CoderEvent,GetMagickModule(),
        "  Creating canvas image with size %lux%lu",(unsigned long) image->rows,
```


### `coders/wpg.c`

```diff
@@ -1413,6 +1413,12 @@ static Image *ReadWPGImage(const ImageInfo *image_info,
          ThrowReaderException(CoderError,"DataEncodingSchemeIsNotSupported");
       }
    }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
 
  Finish:
   (void) CloseBlob(image);
```


### `coders/xbm.c`

```diff
@@ -291,6 +291,12 @@ static Image *ReadXBMImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Initialize hex values.
   */
```


### `coders/xc.c`

```diff
@@ -132,6 +132,12 @@ static Image *ReadXCImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns=1;
   if (image->rows == 0)
     image->rows=1;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   (void) CopyMagickString(image->filename,image_info->filename,MaxTextExtent);
   status=QueryMagickColor((char *) image_info->filename,&color,exception);
   if (status == MagickFalse)
```


### `coders/xcf.c`

```diff
@@ -1275,6 +1275,12 @@ static Image *ReadXCFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       XCFLayerInfo
         *layer_info;
 
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       /*
         The read pointer.
       */
```


### `coders/xpm.c`

```diff
@@ -432,6 +432,12 @@ static Image *ReadXPMImage(const ImageInfo *image_info,ExceptionInfo *exception)
       /*
         Read image pixels.
       */
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       for (y=0; y < (ssize_t) image->rows; y++)
       {
         p=NextXPMLine(p);
```


### `coders/xwd.c`

```diff
@@ -399,6 +399,12 @@ static Image *ReadXWDImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->columns=(size_t) ximage->width;
   image->rows=(size_t) ximage->height;
   image->depth=8;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if ((header.ncolors == 0U) || (ximage->red_mask != 0) ||
       (ximage->green_mask != 0) || (ximage->blue_mask != 0))
     image->storage_class=DirectClass;
```


### `coders/ycbcr.c`

```diff
@@ -149,6 +149,12 @@ static Image *ReadYCBCRImage(const ImageInfo *image_info,
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   SetImageColorspace(image,YCbCrColorspace);
   if (image_info->interlace != PartitionInterlace)
     {
@@ -204,6 +210,12 @@ static Image *ReadYCBCRImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,YCbCrColorspace);
     switch (image_info->interlace)
     {
```


### `coders/yuv.c`

```diff
@@ -146,6 +146,12 @@ static Image *ReadYUVImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   quantum=(size_t) (image->depth <= 8 ? 1 : 2);
   interlace=image_info->interlace;
   horizontal_factor=2;
@@ -213,6 +219,12 @@ static Image *ReadYUVImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (interlace == PartitionInterlace)
       {
         AppendImageFormat("Y",image->filename);
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
