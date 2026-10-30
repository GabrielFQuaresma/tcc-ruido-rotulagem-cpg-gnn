# Pacote de anotacao — caso 22

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

# Evidencia do caso 22

## Identificacao

- projeto: savannah
- CVE: CVE-2010-2527
- CWE atribuida pelo BigVul: CWE-119
- commit: `b995299b73ba4cd259f221f500d4e63095508bec`
- URL do commit: https://git.savannah.gnu.org/cgit/freetype/freetype2-demos.git/commit/?id=b995299b73ba4cd259f221f500d4e63095508bec
- arquivo da funcao marcada: `_ausente_`

## Mensagem do commit

_Nao disponivel neste registro._

## Resumo da CVE

> Multiple buffer overflows in demo programs in FreeType before 2.4.0 allow remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted font file.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -157,7 +157,7 @@
            Render_All( Num, ptsize );
          }
  
-        sprintf( Header, "%s %s (file %s)",
+        sprintf( Header, "%.50s %.50s (file %.100s)",
                           face->family_name,
                           face->style_name,
                           ft_basename( argv[file] ) );
@@ -192,7 +192,7 @@
        }
        else
        {
-        sprintf( Header, "%s: not an MM font file, or could not be opened",
+        sprintf( Header, "%.100s: not an MM font file, or could not be opened",
                           ft_basename( argv[file] ) );
        }
       grWriteCellString( &bit, 0, 8, Header, fore_color );
```

## Corpo completo da funcao antes da correcao

```c
  main( int    argc,
        char*  argv[] )
  {
    int    old_ptsize, orig_ptsize, file;
    int    first_glyph = 0;
    int    XisSetup = 0;
    char*  execname;
    int    option;
    int    file_loaded;

    grEvent  event;


    execname = ft_basename( argv[0] );

    while ( 1 )
    {
      option = getopt( argc, argv, "d:e:f:r:" );

      if ( option == -1 )
        break;

      switch ( option )
      {
      case 'd':
        parse_design_coords( optarg );
        break;

      case 'e':
        encoding = (FT_Encoding)make_tag( optarg );
        break;

      case 'f':
        first_glyph = atoi( optarg );
        break;

      case 'r':
        res = atoi( optarg );
        if ( res < 1 )
          usage( execname );
        break;

      default:
        usage( execname );
        break;
      }
    }

    argc -= optind;
    argv += optind;

    if ( argc <= 1 )
      usage( execname );

    if ( sscanf( argv[0], "%d", &orig_ptsize ) != 1 )
      orig_ptsize = 64;

    file = 1;

    /* Initialize engine */
    error = FT_Init_FreeType( &library );
    if ( error )
      PanicZ( "Could not initialize FreeType library" );

  NewFile:
    ptsize      = orig_ptsize;
    hinted      = 1;
    file_loaded = 0;

    /* Load face */
    error = FT_New_Face( library, argv[file], 0, &face );
    if ( error )
      goto Display_Font;

    if ( encoding != FT_ENCODING_NONE )
    {
      error = FT_Select_Charmap( face, encoding );
      if ( error )
        goto Display_Font;
    }

    /* retrieve multiple master information */
    error = FT_Get_MM_Var( face, &multimaster );
    if ( error )
      goto Display_Font;

    /* if the user specified a position, use it, otherwise */
    /* set the current position to the median of each axis */
    {
      int  n;


      for ( n = 0; n < (int)multimaster->num_axis; n++ )
      {
        design_pos[n] = n < requested_cnt ? requested_pos[n]
                                          : multimaster->axis[n].def;
        if ( design_pos[n] < multimaster->axis[n].minimum )
          design_pos[n] = multimaster->axis[n].minimum;
        else if ( design_pos[n] > multimaster->axis[n].maximum )
          design_pos[n] = multimaster->axis[n].maximum;
      }
    }

    error = FT_Set_Var_Design_Coordinates( face,
                                           multimaster->num_axis,
                                           design_pos );
    if ( error )
      goto Display_Font;

    file_loaded++;

    Reset_Scale( ptsize );

    num_glyphs = face->num_glyphs;
    glyph      = face->glyph;
    size       = face->size;

  Display_Font:
    /* initialize graphics if needed */
    if ( !XisSetup )
    {
      XisSetup = 1;
      Init_Display();
    }

    grSetTitle( surface, "FreeType Glyph Viewer - press F1 for help" );
    old_ptsize = ptsize;

    if ( file_loaded >= 1 )
    {
      Fail = 0;
      Num  = first_glyph;

      if ( Num >= num_glyphs )
        Num = num_glyphs - 1;

      if ( Num < 0 )
        Num = 0;
    }

    for ( ;; )
    {
      int  key;


      Clear_Display();

      if ( file_loaded >= 1 )
      {
        switch ( render_mode )
        {
        case 0:
          Render_Text( Num );
          break;

        default:
           Render_All( Num, ptsize );
         }
 
        sprintf( Header, "%s %s (file %s)",
                          face->family_name,
                          face->style_name,
                          ft_basename( argv[file] ) );

        if ( !new_header )
          new_header = Header;

        grWriteCellString( &bit, 0, 0, new_header, fore_color );
        new_header = 0;

        sprintf( Header, "axis: " );
        {
          int  n;


          for ( n = 0; n < (int)multimaster->num_axis; n++ )
          {
            char  temp[32];


            sprintf( temp, "  %s:%g",
                           multimaster->axis[n].name,
                           design_pos[n]/65536. );
            strcat( Header, temp );
          }
        }
        grWriteCellString( &bit, 0, 16, Header, fore_color );

        sprintf( Header, "at %d points, first glyph = %d",
                         ptsize,
                         Num );
       }
       else
       {
        sprintf( Header, "%s: not an MM font file, or could not be opened",
                          ft_basename( argv[file] ) );
       }
      grWriteCellString( &bit, 0, 8, Header, fore_color );
      grRefreshSurface( surface );

      grListenSurface( surface, 0, &event );
      if ( !( key = Process_Event( &event ) ) )
        goto End;

      if ( key == 'n' )
      {
        if ( file_loaded >= 1 )
          FT_Done_Face( face );

        if ( file < argc - 1 )
          file++;

        goto NewFile;
      }

      if ( key == 'p' )
      {
        if ( file_loaded >= 1 )
          FT_Done_Face( face );

        if ( file > 1 )
          file--;

        goto NewFile;
      }

      if ( ptsize != old_ptsize )
      {
        Reset_Scale( ptsize );

        old_ptsize = ptsize;
      }
    }

  End:
    grDoneSurface( surface );
    grDoneDevices();

    free            ( multimaster );
    FT_Done_Face    ( face        );
    FT_Done_FreeType( library     );

    printf( "Execution completed successfully.\n" );
    printf( "Fails = %d\n", Fail );

    exit( 0 );      /* for safety reasons */
    return 0;       /* never reached */
  }

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
