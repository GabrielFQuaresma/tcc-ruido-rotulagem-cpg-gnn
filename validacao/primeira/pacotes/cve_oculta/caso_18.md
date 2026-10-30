# Pacote de anotacao — caso 18

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

# Evidencia do caso 18

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `ngiflib.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -22,6 +22,24 @@
  	i->width = GetWord(i->parent);	/* SizeX   */
  	i->height = GetWord(i->parent);	/* SizeY   */
  
+	if((i->width > i->parent->width) || (i->height > i->parent->height)) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** ERROR *** Image bigger than global GIF canvas !\n");
+#endif
+		return -1;
+	}
+	if((i->posX + i->width) > i->parent->width) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting X position\n");
+#endif
+		i->posX = i->parent->width - i->width;
+	}
+	if((i->posY + i->height) > i->parent->height) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting Y position\n");
+#endif
+		i->posY = i->parent->height - i->height;
+	}
  	context.Xtogo = i->width;
  	context.curY = i->posY;
  #ifdef NGIFLIB_INDEXED_ONLY
```

## Corpo completo da funcao antes da correcao

```c
static int DecodeGifImg(struct ngiflib_img * i) {
	struct ngiflib_decode_context context;
	long npix;
	u8 * stackp;
	u8 * stack_top;
	u16 clr;
	u16 eof;
	u16 free;
	u16 act_code = 0;
	u16 old_code = 0;
	u16 read_byt;
	u16 ab_prfx[4096];
	u8 ab_suffx[4096];
	u8 ab_stack[4096];
	u8 flags;
	u8 casspecial = 0;

	if(!i) return -1;

	i->posX = GetWord(i->parent);	/* offsetX */
	i->posY = GetWord(i->parent);	/* offsetY */
 	i->width = GetWord(i->parent);	/* SizeX   */
 	i->height = GetWord(i->parent);	/* SizeY   */
 
 	context.Xtogo = i->width;
 	context.curY = i->posY;
 #ifdef NGIFLIB_INDEXED_ONLY
	#ifdef NGIFLIB_ENABLE_CALLBACKS
	context.line_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width;
	context.frbuff_p.p8 = context.line_p.p8 + i->posX;
	#else
	context.frbuff_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width + i->posX;
	#endif /* NGIFLIB_ENABLE_CALLBACKS */
#else
	if(i->parent->mode & NGIFLIB_MODE_INDEXED) {
		#ifdef NGIFLIB_ENABLE_CALLBACKS
		context.line_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width;
		context.frbuff_p.p8 = context.line_p.p8 + i->posX;
		#else
		context.frbuff_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width + i->posX;
		#endif /* NGIFLIB_ENABLE_CALLBACKS */
	} else {
		#ifdef NGIFLIB_ENABLE_CALLBACKS
		context.line_p.p32 = i->parent->frbuff.p32 + (u32)i->posY*i->parent->width;
		context.frbuff_p.p32 = context.line_p.p32 + i->posX;
		#else
		context.frbuff_p.p32 = i->parent->frbuff.p32 + (u32)i->posY*i->parent->width + i->posX;
		#endif /* NGIFLIB_ENABLE_CALLBACKS */
	}
#endif /* NGIFLIB_INDEXED_ONLY */

	npix = (long)i->width * i->height;
	flags = GetByte(i->parent);
	i->interlaced = (flags & 64) >> 6;
	context.pass = i->interlaced ? 1 : 0;
	i->sort_flag = (flags & 32) >> 5;	/* is local palette sorted by color frequency ? */
	i->localpalbits = (flags & 7) + 1;
	if(flags&128) { /* palette locale */
		int k;
		int localpalsize = 1 << i->localpalbits;
#if !defined(NGIFLIB_NO_FILE)
		if(i->parent && i->parent->log) fprintf(i->parent->log, "Local palette\n");
#endif /* !defined(NGIFLIB_NO_FILE) */
		i->palette = (struct ngiflib_rgb *)ngiflib_malloc(sizeof(struct ngiflib_rgb)*localpalsize);
		for(k=0; k<localpalsize; k++) {
			i->palette[k].r = GetByte(i->parent);
			i->palette[k].g = GetByte(i->parent);
			i->palette[k].b = GetByte(i->parent);
		}
#ifdef NGIFLIB_ENABLE_CALLBACKS
		if(i->parent->palette_cb) i->parent->palette_cb(i->parent, i->palette, localpalsize);
#endif /* NGIFLIB_ENABLE_CALLBACKS */
	} else {
		i->palette = i->parent->palette;
		i->localpalbits = i->parent->imgbits;
	}
	i->ncolors = 1 << i->localpalbits;
	
	i->imgbits = GetByte(i->parent);	/* LZW Minimum Code Size */

#if !defined(NGIFLIB_NO_FILE)
	if(i->parent && i->parent->log) {
		if(i->interlaced) fprintf(i->parent->log, "interlaced ");
		fprintf(i->parent->log, "img pos(%hu,%hu) size %hux%hu palbits=%hhu imgbits=%hhu ncolors=%hu\n",
	       i->posX, i->posY, i->width, i->height, i->localpalbits, i->imgbits, i->ncolors);
	}
#endif /* !defined(NGIFLIB_NO_FILE) */

	if(i->imgbits==1) {	/* fix for 1bit images ? */
		i->imgbits = 2;
	}
	clr = 1 << i->imgbits;
	eof = clr + 1;
	free = clr + 2;
	context.nbbit = i->imgbits + 1;
	context.max = clr + clr - 1; /* (1 << context.nbbit) - 1 */
	stackp = stack_top = ab_stack + 4096;
	
	context.restbits = 0;	/* initialise le "buffer" de lecture */
	context.restbyte = 0;	/* des codes LZW */
	context.lbyte = 0;
	for(;;) {
		act_code = GetGifWord(i, &context);
		if(act_code==eof) {
#if !defined(NGIFLIB_NO_FILE)
			if(i->parent && i->parent->log) fprintf(i->parent->log, "End of image code\n");
#endif /* !defined(NGIFLIB_NO_FILE) */
			return 0;
		}
		if(npix==0) {
#if !defined(NGIFLIB_NO_FILE)
			if(i->parent && i->parent->log) fprintf(i->parent->log, "assez de pixels, On se casse !\n");
#endif /* !defined(NGIFLIB_NO_FILE) */
			return 1;
		}	
		if(act_code==clr) {
#if !defined(NGIFLIB_NO_FILE)
			if(i->parent && i->parent->log) fprintf(i->parent->log, "Code clear (free=%hu) npix=%ld\n", free, npix);
#endif /* !defined(NGIFLIB_NO_FILE) */
			/* clear */
			free = clr + 2;
			context.nbbit = i->imgbits + 1;
			context.max = clr + clr - 1; /* (1 << context.nbbit) - 1 */
			act_code = GetGifWord(i, &context);
			casspecial = (u8)act_code;
			old_code = act_code;
			WritePixel(i, &context, casspecial); npix--;
		} else {
			read_byt = act_code;
			if(act_code >= free) {	/* code pas encore dans alphabet */
/*				printf("Code pas dans alphabet : %d>=%d push %d\n", act_code, free, casspecial); */
				*(--stackp) = casspecial; /* dernier debut de chaine ! */
				act_code = old_code;
			}
/*			printf("actcode=%d\n", act_code); */
			while(act_code > clr) { /* code non concret */
				/* fillstackloop empile les suffixes ! */
				*(--stackp) = ab_suffx[act_code];
				act_code = ab_prfx[act_code];	/* prefixe */
			}
			/* act_code est concret */
			casspecial = (u8)act_code;	/* dernier debut de chaine ! */
			*(--stackp) = casspecial;	/* push on stack */
			WritePixels(i, &context, stackp, stack_top - stackp);	/* unstack all pixels at once */
			npix -= (stack_top - stackp);
			stackp = stack_top;
/*			putchar('\n'); */
			if(free < 4096) { /* la taille du dico est 4096 max ! */
				ab_prfx[free] = old_code;
				ab_suffx[free] = (u8)act_code;
				free++;
				if((free > context.max) && (context.nbbit < 12)) {
					context.nbbit++;	/* 1 bit de plus pour les codes LZW */
					context.max += context.max + 1;
				}
			}
			old_code = read_byt;
		}
			
	}
	return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `ngiflib.c` **(funcao marcada esta aqui)** | modified | 18 | 0 |


### `ngiflib.c`

```diff
@@ -408,6 +408,24 @@ static int DecodeGifImg(struct ngiflib_img * i) {
 	i->width = GetWord(i->parent);	/* SizeX   */
 	i->height = GetWord(i->parent);	/* SizeY   */
 
+	if((i->width > i->parent->width) || (i->height > i->parent->height)) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** ERROR *** Image bigger than global GIF canvas !\n");
+#endif
+		return -1;
+	}
+	if((i->posX + i->width) > i->parent->width) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting X position\n");
+#endif
+		i->posX = i->parent->width - i->width;
+	}
+	if((i->posY + i->height) > i->parent->height) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting Y position\n");
+#endif
+		i->posY = i->parent->height - i->height;
+	}
 	context.Xtogo = i->width;
 	context.curY = i->posY;
 #ifdef NGIFLIB_INDEXED_ONLY
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
