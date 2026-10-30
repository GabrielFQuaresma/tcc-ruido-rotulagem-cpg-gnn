# Pacote de anotacao — caso 23

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

# Evidencia do caso 23

## Identificacao

- projeto: curl
- CVE: CVE-2016-9586
- CWE atribuida pelo BigVul: CWE-119
- commit: `curl-7_51_0-162-g3ab3c16`
- URL do commit: https://github.com/curl/curl/commit/curl-7_51_0-162-g3ab3c16
- arquivo da funcao marcada: `lib/mprintf.c`

## Mensagem do commit

> printf: fix floating point buffer overflow issues
> 
> ... and add a bunch of floating point printf tests

## Resumo da CVE

> curl before version 7.52.0 is vulnerable to a buffer overflow when doing a large floating point output in libcurl's implementation of the printf() functions. If there are any application that accepts a format string from the outside without necessary input filtering, it could allow remote attacks.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -356,12 +356,25 @@
          *fptr = 0;
  
          if(width >= 0) {
+          if(width >= (long)sizeof(work))
+            width = sizeof(work)-1;
            /* RECURSIVE USAGE */
            len = curl_msnprintf(fptr, left, "%ld", width);
            fptr += len;
            left -= len;
          }
          if(prec >= 0) {
+          /* for each digit in the integer part, we can have one less
+             precision */
+          size_t maxprec = sizeof(work) - 2;
+          double val = p->data.dnum;
+          while(val >= 10.0) {
+            val /= 10;
+            maxprec--;
+          }
+
+          if(prec > (long)maxprec)
+            prec = maxprec-1;
            /* RECURSIVE USAGE */
            len = curl_msnprintf(fptr, left, ".%ld", prec);
            fptr += len;
@@ -381,6 +394,9 @@
          /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
             output characters */
          (sprintf)(work, formatbuf, p->data.dnum);
+#ifdef CURLDEBUG
+        assert(strlen(work) <= sizeof(work));
+#endif
          for(fptr=work; *fptr; fptr++)
            OUTCHAR(*fptr);
        }
```

## Corpo completo da funcao antes da correcao

```c
static int dprintf_formatf(
  void *data, /* untouched by format(), just sent to the stream() function in
                 the second argument */
  /* function pointer called for each output character */
  int (*stream)(int, FILE *),
  const char *format,    /* %-formatted string */
  va_list ap_save) /* list of parameters */
{
  /* Base-36 digits for numbers.  */
  const char *digits = lower_digits;

  /* Pointer into the format string.  */
  char *f;

  /* Number of characters written.  */
  int done = 0;

  long param; /* current parameter to read */
  long param_num=0; /* parameter counter */

  va_stack_t vto[MAX_PARAMETERS];
  char *endpos[MAX_PARAMETERS];
  char **end;

  char work[BUFFSIZE];

  va_stack_t *p;

  /* 'workend' points to the final buffer byte position, but with an extra
     byte as margin to avoid the (false?) warning Coverity gives us
     otherwise */
  char *workend = &work[sizeof(work) - 2];

  /* Do the actual %-code parsing */
  if(dprintf_Pass1(format, vto, endpos, ap_save))
    return -1;

  end = &endpos[0]; /* the initial end-position from the list dprintf_Pass1()
                       created for us */

  f = (char *)format;
  while(*f != '\0') {
    /* Format spec modifiers.  */
    int is_alt;

    /* Width of a field.  */
    long width;

    /* Precision of a field.  */
    long prec;

    /* Decimal integer is negative.  */
    int is_neg;

    /* Base of a number to be written.  */
    long base;

    /* Integral values to be written.  */
    mp_uintmax_t num;

    /* Used to convert negative in positive.  */
    mp_intmax_t signed_num;

    char *w;

    if(*f != '%') {
      /* This isn't a format spec, so write everything out until the next one
         OR end of string is reached.  */
      do {
        OUTCHAR(*f);
      } while(*++f && ('%' != *f));
      continue;
    }

    ++f;

    /* Check for "%%".  Note that although the ANSI standard lists
       '%' as a conversion specifier, it says "The complete format
       specification shall be `%%'," so we can avoid all the width
       and precision processing.  */
    if(*f == '%') {
      ++f;
      OUTCHAR('%');
      continue;
    }

    /* If this is a positional parameter, the position must follow immediately
       after the %, thus create a %<num>$ sequence */
    param=dprintf_DollarString(f, &f);

    if(!param)
      param = param_num;
    else
      --param;

    param_num++; /* increase this always to allow "%2$s %1$s %s" and then the
                    third %s will pick the 3rd argument */

    p = &vto[param];

    /* pick up the specified width */
    if(p->flags & FLAGS_WIDTHPARAM) {
      width = (long)vto[p->width].data.num.as_signed;
      param_num++; /* since the width is extracted from a parameter, we
                      must skip that to get to the next one properly */
      if(width < 0) {
        /* "A negative field width is taken as a '-' flag followed by a
           positive field width." */
        width = -width;
        p->flags |= FLAGS_LEFT;
        p->flags &= ~FLAGS_PAD_NIL;
      }
    }
    else
      width = p->width;

    /* pick up the specified precision */
    if(p->flags & FLAGS_PRECPARAM) {
      prec = (long)vto[p->precision].data.num.as_signed;
      param_num++; /* since the precision is extracted from a parameter, we
                      must skip that to get to the next one properly */
      if(prec < 0)
        /* "A negative precision is taken as if the precision were
           omitted." */
        prec = -1;
    }
    else if(p->flags & FLAGS_PREC)
      prec = p->precision;
    else
      prec = -1;

    is_alt = (p->flags & FLAGS_ALT) ? 1 : 0;

    switch(p->type) {
    case FORMAT_INT:
      num = p->data.num.as_unsigned;
      if(p->flags & FLAGS_CHAR) {
        /* Character.  */
        if(!(p->flags & FLAGS_LEFT))
          while(--width > 0)
            OUTCHAR(' ');
        OUTCHAR((char) num);
        if(p->flags & FLAGS_LEFT)
          while(--width > 0)
            OUTCHAR(' ');
        break;
      }
      if(p->flags & FLAGS_OCTAL) {
        /* Octal unsigned integer.  */
        base = 8;
        goto unsigned_number;
      }
      else if(p->flags & FLAGS_HEX) {
        /* Hexadecimal unsigned integer.  */

        digits = (p->flags & FLAGS_UPPER)? upper_digits : lower_digits;
        base = 16;
        goto unsigned_number;
      }
      else if(p->flags & FLAGS_UNSIGNED) {
        /* Decimal unsigned integer.  */
        base = 10;
        goto unsigned_number;
      }

      /* Decimal integer.  */
      base = 10;

      is_neg = (p->data.num.as_signed < (mp_intmax_t)0) ? 1 : 0;
      if(is_neg) {
        /* signed_num might fail to hold absolute negative minimum by 1 */
        signed_num = p->data.num.as_signed + (mp_intmax_t)1;
        signed_num = -signed_num;
        num = (mp_uintmax_t)signed_num;
        num += (mp_uintmax_t)1;
      }

      goto number;

      unsigned_number:
      /* Unsigned number of base BASE.  */
      is_neg = 0;

      number:
      /* Number of base BASE.  */

      /* Supply a default precision if none was given.  */
      if(prec == -1)
        prec = 1;

      /* Put the number in WORK.  */
      w = workend;
      while(num > 0) {
        *w-- = digits[num % base];
        num /= base;
      }
      width -= (long)(workend - w);
      prec -= (long)(workend - w);

      if(is_alt && base == 8 && prec <= 0) {
        *w-- = '0';
        --width;
      }

      if(prec > 0) {
        width -= prec;
        while(prec-- > 0)
          *w-- = '0';
      }

      if(is_alt && base == 16)
        width -= 2;

      if(is_neg || (p->flags & FLAGS_SHOWSIGN) || (p->flags & FLAGS_SPACE))
        --width;

      if(!(p->flags & FLAGS_LEFT) && !(p->flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR(' ');

      if(is_neg)
        OUTCHAR('-');
      else if(p->flags & FLAGS_SHOWSIGN)
        OUTCHAR('+');
      else if(p->flags & FLAGS_SPACE)
        OUTCHAR(' ');

      if(is_alt && base == 16) {
        OUTCHAR('0');
        if(p->flags & FLAGS_UPPER)
          OUTCHAR('X');
        else
          OUTCHAR('x');
      }

      if(!(p->flags & FLAGS_LEFT) && (p->flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR('0');

      /* Write the number.  */
      while(++w <= workend) {
        OUTCHAR(*w);
      }

      if(p->flags & FLAGS_LEFT)
        while(width-- > 0)
          OUTCHAR(' ');
      break;

    case FORMAT_STRING:
            /* String.  */
      {
        static const char null[] = "(nil)";
        const char *str;
        size_t len;

        str = (char *) p->data.str;
        if(str == NULL) {
          /* Write null[] if there's space.  */
          if(prec == -1 || prec >= (long) sizeof(null) - 1) {
            str = null;
            len = sizeof(null) - 1;
            /* Disable quotes around (nil) */
            p->flags &= (~FLAGS_ALT);
          }
          else {
            str = "";
            len = 0;
          }
        }
        else if(prec != -1)
          len = (size_t)prec;
        else
          len = strlen(str);

        width -= (len > LONG_MAX) ? LONG_MAX : (long)len;

        if(p->flags & FLAGS_ALT)
          OUTCHAR('"');

        if(!(p->flags&FLAGS_LEFT))
          while(width-- > 0)
            OUTCHAR(' ');

        while((len-- > 0) && *str)
          OUTCHAR(*str++);
        if(p->flags&FLAGS_LEFT)
          while(width-- > 0)
            OUTCHAR(' ');

        if(p->flags & FLAGS_ALT)
          OUTCHAR('"');
      }
      break;

    case FORMAT_PTR:
      /* Generic pointer.  */
      {
        void *ptr;
        ptr = (void *) p->data.ptr;
        if(ptr != NULL) {
          /* If the pointer is not NULL, write it as a %#x spec.  */
          base = 16;
          digits = (p->flags & FLAGS_UPPER)? upper_digits : lower_digits;
          is_alt = 1;
          num = (size_t) ptr;
          is_neg = 0;
          goto number;
        }
        else {
          /* Write "(nil)" for a nil pointer.  */
          static const char strnil[] = "(nil)";
          const char *point;

          width -= (long)(sizeof(strnil) - 1);
          if(p->flags & FLAGS_LEFT)
            while(width-- > 0)
              OUTCHAR(' ');
          for(point = strnil; *point != '\0'; ++point)
            OUTCHAR(*point);
          if(! (p->flags & FLAGS_LEFT))
            while(width-- > 0)
              OUTCHAR(' ');
        }
      }
      break;

    case FORMAT_DOUBLE:
      {
        char formatbuf[32]="%";
        char *fptr = &formatbuf[1];
        size_t left = sizeof(formatbuf)-strlen(formatbuf);
        int len;

        width = -1;
        if(p->flags & FLAGS_WIDTH)
          width = p->width;
        else if(p->flags & FLAGS_WIDTHPARAM)
          width = (long)vto[p->width].data.num.as_signed;

        prec = -1;
        if(p->flags & FLAGS_PREC)
          prec = p->precision;
        else if(p->flags & FLAGS_PRECPARAM)
          prec = (long)vto[p->precision].data.num.as_signed;

        if(p->flags & FLAGS_LEFT)
          *fptr++ = '-';
        if(p->flags & FLAGS_SHOWSIGN)
          *fptr++ = '+';
        if(p->flags & FLAGS_SPACE)
          *fptr++ = ' ';
        if(p->flags & FLAGS_ALT)
          *fptr++ = '#';

         *fptr = 0;
 
         if(width >= 0) {
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, "%ld", width);
           fptr += len;
           left -= len;
         }
         if(prec >= 0) {
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, ".%ld", prec);
           fptr += len;
        }
        if(p->flags & FLAGS_LONG)
          *fptr++ = 'l';

        if(p->flags & FLAGS_FLOATE)
          *fptr++ = (char)((p->flags & FLAGS_UPPER) ? 'E':'e');
        else if(p->flags & FLAGS_FLOATG)
          *fptr++ = (char)((p->flags & FLAGS_UPPER) ? 'G' : 'g');
        else
          *fptr++ = 'f';

        *fptr = 0; /* and a final zero termination */

         /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
            output characters */
         (sprintf)(work, formatbuf, p->data.dnum);
         for(fptr=work; *fptr; fptr++)
           OUTCHAR(*fptr);
       }
      break;

    case FORMAT_INTPTR:
      /* Answer the count of characters written.  */
#ifdef HAVE_LONG_LONG_TYPE
      if(p->flags & FLAGS_LONGLONG)
        *(LONG_LONG_TYPE *) p->data.ptr = (LONG_LONG_TYPE)done;
      else
#endif
        if(p->flags & FLAGS_LONG)
          *(long *) p->data.ptr = (long)done;
      else if(!(p->flags & FLAGS_SHORT))
        *(int *) p->data.ptr = (int)done;
      else
        *(short *) p->data.ptr = (short)done;
      break;

    default:
      break;
    }
    f = *end++; /* goto end of %-code */

  }
  return done;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `lib/mprintf.c` **(funcao marcada esta aqui)** | modified | 18 | 2 |
| `tests/data/test557` | modified | 1 | 0 |
| `tests/libtest/lib557.c` | modified | 133 | 3 |


### `lib/mprintf.c`

```diff
@@ -92,7 +92,8 @@
 #  define mp_uintmax_t unsigned long
 #endif
 
-#define BUFFSIZE 256 /* buffer for long-to-str and float-to-str calcs */
+#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
+                        fit negative DBL_MAX (317 letters) */
 #define MAX_PARAMETERS 128 /* lame static limit */
 
 #ifdef __AMIGA__
@@ -916,12 +917,25 @@ static int dprintf_formatf(
         *fptr = 0;
 
         if(width >= 0) {
+          if(width >= (long)sizeof(work))
+            width = sizeof(work)-1;
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, "%ld", width);
           fptr += len;
           left -= len;
         }
         if(prec >= 0) {
+          /* for each digit in the integer part, we can have one less
+             precision */
+          size_t maxprec = sizeof(work) - 2;
+          double val = p->data.dnum;
+          while(val >= 10.0) {
+            val /= 10;
+            maxprec--;
+          }
+
+          if(prec > (long)maxprec)
+            prec = maxprec-1;
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, ".%ld", prec);
           fptr += len;
@@ -941,7 +955,9 @@ static int dprintf_formatf(
         /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
            output characters */
         (sprintf)(work, formatbuf, p->data.dnum);
-
+#ifdef CURLDEBUG
+        assert(strlen(work) <= sizeof(work));
+#endif
         for(fptr=work; *fptr; fptr++)
           OUTCHAR(*fptr);
       }
```


### `tests/data/test557`

```diff
@@ -40,6 +40,7 @@ All curl_mprintf() unsigned long tests OK!
 All curl_mprintf() signed long tests OK!
 All curl_mprintf() curl_off_t tests OK!
 All curl_mprintf() strings tests OK!
+All float strings tests OK!
 </stdout>
 </verify>
 
```


### `tests/libtest/lib557.c`

```diff
@@ -1374,16 +1374,31 @@ static int test_curl_off_t_formatting(void)
   return failed;
 }
 
-static int string_check(char *buf, const char *buf2)
+static int _string_check(int linenumber, char *buf, const char *buf2)
 {
   if(strcmp(buf, buf2)) {
     /* they shouldn't differ */
-    printf("sprintf failed:\nwe '%s'\nsystem: '%s'\n",
-           buf, buf2);
+    printf("sprintf line %d failed:\nwe      '%s'\nsystem: '%s'\n",
+           linenumber, buf, buf2);
     return 1;
   }
   return 0;
 }
+#define string_check(x,y) _string_check(__LINE__, x, y)
+
+static int _strlen_check(int linenumber, char *buf, size_t len)
+{
+  size_t buflen = strlen(buf);
+  if(len != buflen) {
+    /* they shouldn't differ */
+    printf("sprintf strlen:%d failed:\nwe '%d'\nsystem: '%d'\n",
+           linenumber, buflen, len);
+    return 1;
+  }
+  return 0;
+}
+
+#define strlen_check(x,y) _strlen_check(__LINE__, x, y)
 
 /*
  * The output strings in this test need to have been verified with a system
@@ -1523,6 +1538,119 @@ static int test_weird_arguments(void)
   return errors;
 }
 
+/* DBL_MAX value from Linux */
+#define MAXIMIZE -179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.000000
+
+static int test_float_formatting(void)
+{
+  int errors = 0;
+  char buf[512]; /* larger than max float size */
+  curl_msnprintf(buf, sizeof(buf), "%f", 9.0);
+  errors += string_check(buf, "9.000000");
+
+  curl_msnprintf(buf, sizeof(buf), "%.1f", 9.1);
+  errors += string_check(buf, "9.1");
+
+  curl_msnprintf(buf, sizeof(buf), "%.2f", 9.1);
+  errors += string_check(buf, "9.10");
+
+  curl_msnprintf(buf, sizeof(buf), "%.0f", 9.1);
+  errors += string_check(buf, "9");
+
+  curl_msnprintf(buf, sizeof(buf), "%0f", 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%10f", 9.1);
+  errors += string_check(buf, "  9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%10.3f", 9.1);
+  errors += string_check(buf, "     9.100");
+
+  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.1);
+  errors += string_check(buf, "9.100     ");
+
+  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.123456);
+  errors += string_check(buf, "9.123     ");
+
+  curl_msnprintf(buf, sizeof(buf), "%.-2f", 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 10, 9.1);
+  errors += string_check(buf, "  9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 3, 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.2987654);
+  errors += string_check(buf, "9.298765");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.298765);
+  errors += string_check(buf, "9.298765");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.29876);
+  errors += string_check(buf, "9.298760");
+
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 6, 9.2987654);
+  errors += string_check(buf, "9.298765");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 5, 9.2987654);
+  errors += string_check(buf, "9.29877");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 4, 9.2987654);
+  errors += string_check(buf, "9.2988");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 3, 9.2987654);
+  errors += string_check(buf, "9.299");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 2, 9.2987654);
+  errors += string_check(buf, "9.30");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 1, 9.2987654);
+  errors += string_check(buf, "9.3");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 0, 9.2987654);
+  errors += string_check(buf, "9");
+
+  /* very large precisions easily turn into system specific outputs so we only
+     check the output buffer length here as we know the internal limit */
+
+  curl_msnprintf(buf, sizeof(buf), "%.*f", (1<<30), 9.2987654);
+  errors += strlen_check(buf, 325);
+
+  curl_msnprintf(buf, sizeof(buf), "%10000.10000f", 9.2987654);
+  errors += strlen_check(buf, 325);
+
+  curl_msnprintf(buf, sizeof(buf), "%240.10000f",
+                 123456789123456789123456789.2987654);
+  errors += strlen_check(buf, 325);
+
+  /* 1<<31 turns negative (-2147483648) when used signed */
+  curl_msnprintf(buf, sizeof(buf), "%*f", (1<<31), 9.1);
+  errors += string_check(buf, "9.100000");
+
+  /* curl_msnprintf() limits a single float output to 325 bytes maximum
+     width */
+  curl_msnprintf(buf, sizeof(buf), "%*f", (1<<30), 9.1);
+  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");
+  curl_msnprintf(buf, sizeof(buf), "%100000f", 9.1);
+  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%f", MAXIMIZE);
+  errors += strlen_check(buf, 317);
+
+  curl_msnprintf(buf, 2, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 1);
+  curl_msnprintf(buf, 3, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 2);
+  curl_msnprintf(buf, 4, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 3);
+  curl_msnprintf(buf, 5, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 4);
+  curl_msnprintf(buf, 6, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 5);
+
+  if(!errors)
+    printf("All float strings tests OK!\n");
+  else
+    printf("test_float_formatting Failed!\n");
+
+  return errors;
+}
+
 
 int test(char *URL)
 {
@@ -1547,6 +1675,8 @@ int test(char *URL)
 
   errors += test_string_formatting();
 
+  errors += test_float_formatting();
+
   if(errors)
     return TEST_ERR_MAJOR_BAD;
   else
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
