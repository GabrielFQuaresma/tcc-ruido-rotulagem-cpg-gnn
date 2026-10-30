# Pacote de anotacao — caso 04

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

# Evidencia do caso 04

## Identificacao

- projeto: Chrome
- CVE: CVE-2013-2877
- CWE atribuida pelo BigVul: CWE-119
- commit: `d0947db40187f4708c58e64cbd6013faf9eddeed`
- URL do commit: https://github.com/chromium/chromium/commit/d0947db40187f4708c58e64cbd6013faf9eddeed
- arquivo da funcao marcada: `third_party/libxml/src/parser.c`

## Mensagem do commit

> libxml: XML_PARSER_EOF checks from upstream
> 
> BUG=229019
> TBR=cpu
> 
> Review URL: https://chromiumcodereview.appspot.com/14053009
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@196804 0039d316-1c4b-4281-b951-d872f2087c98

## Resumo da CVE

> parser.c in libxml2 before 2.9.0, as used in Google Chrome before 28.0.1500.71 and other products, allows remote attackers to cause a denial of service (out-of-bounds read) via a document that ends abruptly, related to the lack of certain checks for the XML_PARSER_EOF state.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -121,6 +121,8 @@
       * Parse the content of the element:
       */
      xmlParseContent(ctxt);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return;
      if (!IS_BYTE_CHAR(RAW)) {
          xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_TAG_NOT_FINISHED,
  	 "Premature end of data in tag %s line %d\n",
```

## Corpo completo da funcao antes da correcao

```c
xmlParseElement(xmlParserCtxtPtr ctxt) {
    const xmlChar *name;
    const xmlChar *prefix = NULL;
    const xmlChar *URI = NULL;
    xmlParserNodeInfo node_info;
    int line, tlen;
    xmlNodePtr ret;
    int nsNr = ctxt->nsNr;

    if (((unsigned int) ctxt->nameNr > xmlParserMaxDepth) &&
        ((ctxt->options & XML_PARSE_HUGE) == 0)) {
	xmlFatalErrMsgInt(ctxt, XML_ERR_INTERNAL_ERROR,
		 "Excessive depth in document: %d use XML_PARSE_HUGE option\n",
			  xmlParserMaxDepth);
	ctxt->instate = XML_PARSER_EOF;
	return;
    }

    /* Capture start position */
    if (ctxt->record_info) {
        node_info.begin_pos = ctxt->input->consumed +
                          (CUR_PTR - ctxt->input->base);
	node_info.begin_line = ctxt->input->line;
    }

    if (ctxt->spaceNr == 0)
	spacePush(ctxt, -1);
    else if (*ctxt->space == -2)
	spacePush(ctxt, -1);
    else
	spacePush(ctxt, *ctxt->space);

    line = ctxt->input->line;
#ifdef LIBXML_SAX1_ENABLED
    if (ctxt->sax2)
#endif /* LIBXML_SAX1_ENABLED */
        name = xmlParseStartTag2(ctxt, &prefix, &URI, &tlen);
#ifdef LIBXML_SAX1_ENABLED
    else
	name = xmlParseStartTag(ctxt);
#endif /* LIBXML_SAX1_ENABLED */
    if (ctxt->instate == XML_PARSER_EOF)
	return;
    if (name == NULL) {
	spacePop(ctxt);
        return;
    }
    namePush(ctxt, name);
    ret = ctxt->node;

#ifdef LIBXML_VALID_ENABLED
    /*
     * [ VC: Root Element Type ]
     * The Name in the document type declaration must match the element
     * type of the root element. 
     */
    if (ctxt->validate && ctxt->wellFormed && ctxt->myDoc &&
        ctxt->node && (ctxt->node == ctxt->myDoc->children))
        ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);
#endif /* LIBXML_VALID_ENABLED */

    /*
     * Check for an Empty Element.
     */
    if ((RAW == '/') && (NXT(1) == '>')) {
        SKIP(2);
	if (ctxt->sax2) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->endElementNs != NULL) &&
		(!ctxt->disableSAX))
		ctxt->sax->endElementNs(ctxt->userData, name, prefix, URI);
#ifdef LIBXML_SAX1_ENABLED
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL) &&
		(!ctxt->disableSAX))
		ctxt->sax->endElement(ctxt->userData, name);
#endif /* LIBXML_SAX1_ENABLED */
	}
	namePop(ctxt);
	spacePop(ctxt);
	if (nsNr != ctxt->nsNr)
	    nsPop(ctxt, ctxt->nsNr - nsNr);
	if ( ret != NULL && ctxt->record_info ) {
	   node_info.end_pos = ctxt->input->consumed +
			      (CUR_PTR - ctxt->input->base);
	   node_info.end_line = ctxt->input->line;
	   node_info.node = ret;
	   xmlParserAddNodeInfo(ctxt, &node_info);
	}
	return;
    }
    if (RAW == '>') {
        NEXT1;
    } else {
        xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_GT_REQUIRED,
		     "Couldn't find end of Start Tag %s line %d\n",
		                name, line, NULL);

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	namePop(ctxt);
	spacePop(ctxt);
	if (nsNr != ctxt->nsNr)
	    nsPop(ctxt, ctxt->nsNr - nsNr);

	/*
	 * Capture end position and add node
	 */
	if ( ret != NULL && ctxt->record_info ) {
	   node_info.end_pos = ctxt->input->consumed +
			      (CUR_PTR - ctxt->input->base);
	   node_info.end_line = ctxt->input->line;
	   node_info.node = ret;
	   xmlParserAddNodeInfo(ctxt, &node_info);
	}
	return;
    }

    /*
      * Parse the content of the element:
      */
     xmlParseContent(ctxt);
     if (!IS_BYTE_CHAR(RAW)) {
         xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_TAG_NOT_FINISHED,
 	 "Premature end of data in tag %s line %d\n",
		                name, line, NULL);

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	namePop(ctxt);
	spacePop(ctxt);
	if (nsNr != ctxt->nsNr)
	    nsPop(ctxt, ctxt->nsNr - nsNr);
	return;
    }

    /*
     * parse the end of tag: '</' should be here.
     */
    if (ctxt->sax2) {
	xmlParseEndTag2(ctxt, prefix, URI, line, ctxt->nsNr - nsNr, tlen);
	namePop(ctxt);
    }
#ifdef LIBXML_SAX1_ENABLED
      else
	xmlParseEndTag1(ctxt, line);
#endif /* LIBXML_SAX1_ENABLED */

    /*
     * Capture end position and add node
     */
    if ( ret != NULL && ctxt->record_info ) {
       node_info.end_pos = ctxt->input->consumed +
                          (CUR_PTR - ctxt->input->base);
       node_info.end_line = ctxt->input->line;
       node_info.node = ret;
       xmlParserAddNodeInfo(ctxt, &node_info);
    }
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/libxml/README.chromium` | modified | 1 | 0 |
| `third_party/libxml/src/include/libxml/xmlerror.h` | modified | 1 | 0 |
| `third_party/libxml/src/parser.c` **(funcao marcada esta aqui)** | modified | 174 | 27 |


### `third_party/libxml/src/parser.c`

```diff
@@ -2013,6 +2013,8 @@ xmlPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
 		"Pushing input %d : %.30s\n", ctxt->inputNr+1, input->cur);
     }
     ret = inputPush(ctxt, input);
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(-1);
     GROW;
     return(ret);
 }
@@ -2049,6 +2051,8 @@ xmlParseCharRef(xmlParserCtxtPtr ctxt) {
 	    if (count++ > 20) {
 		count = 0;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(0);
 	    }
 	    if ((RAW >= '0') && (RAW <= '9')) 
 	        val = val * 16 + (CUR - '0');
@@ -2080,6 +2084,8 @@ xmlParseCharRef(xmlParserCtxtPtr ctxt) {
 	    if (count++ > 20) {
 		count = 0;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(0);
 	    }
 	    if ((RAW >= '0') && (RAW <= '9')) 
 	        val = val * 10 + (CUR - '0');
@@ -2366,6 +2372,8 @@ xmlParserHandlePEReference(xmlParserCtxtPtr ctxt) {
 	    NEXT;
 	    if ((ctxt->sax != NULL) && (ctxt->sax->getParameterEntity != NULL))
 		entity = ctxt->sax->getParameterEntity(ctxt->userData, name);
+	    if (ctxt->instate == XML_PARSER_EOF)
+	        return;
 	    if (entity == NULL) {
 	        
 		/*
@@ -2428,6 +2436,8 @@ xmlParserHandlePEReference(xmlParserCtxtPtr ctxt) {
 		     * the amount of data in the buffer.
 		     */
 		    GROW
+                    if (ctxt->instate == XML_PARSER_EOF)
+                        return;
 		    if ((ctxt->input->end - ctxt->input->cur)>=4) {
 			start[0] = RAW;
 			start[1] = NXT(1);
@@ -3046,6 +3056,8 @@ xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
      * Handler for more complex cases
      */
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(NULL);
     c = CUR_CHAR(l);
     if ((ctxt->options & XML_PARSE_OLD10) == 0) {
         /*
@@ -3097,6 +3109,8 @@ xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
 	    if (count++ > 100) {
 		count = 0;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 	    }
 	    len += l;
 	    NEXTL(l);
@@ -3121,6 +3135,8 @@ xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
 	    if (count++ > 100) {
 		count = 0;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 	    }
 	    len += l;
 	    NEXTL(l);
@@ -3214,6 +3230,8 @@ xmlParseNCNameComplex(xmlParserCtxtPtr ctxt) {
 	if (count++ > 100) {
 	    count = 0;
 	    GROW;
+            if (ctxt->instate == XML_PARSER_EOF)
+                return(NULL);
 	}
 	len += l;
 	NEXTL(l);
@@ -3294,6 +3312,8 @@ xmlParseNameAndCompare(xmlParserCtxtPtr ctxt, xmlChar const *other) {
     const xmlChar *ret;
 
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(NULL);
 
     in = ctxt->input->cur;
     while (*in != 0 && *in == *cmp) {
@@ -3421,6 +3441,8 @@ xmlParseNmtoken(xmlParserCtxtPtr ctxt) {
 #endif
 
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(NULL);
     c = CUR_CHAR(l);
 
     while (xmlIsNameChar(ctxt, c)) {
@@ -3449,6 +3471,10 @@ xmlParseNmtoken(xmlParserCtxtPtr ctxt) {
 		if (count++ > 100) {
 		    count = 0;
 		    GROW;
+                    if (ctxt->instate == XML_PARSER_EOF) {
+                        xmlFree(buffer);
+                        return(NULL);
+                    }
 		}
 		if (len + 10 > max) {
 		    xmlChar *tmp;
@@ -3519,6 +3545,10 @@ xmlParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
     ctxt->instate = XML_PARSER_ENTITY_VALUE;
     input = ctxt->input;
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF) {
+        xmlFree(buf);
+        return(NULL);
+    }
     NEXT;
     c = CUR_CHAR(l);
     /*
@@ -3530,8 +3560,8 @@ xmlParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
      * In practice it means we stop the loop only when back at parsing
      * the initial entity and the quote is found
      */
-    while ((IS_CHAR(c)) && ((c != stop) || /* checked */
-	   (ctxt->input != input))) {
+    while (((IS_CHAR(c)) && ((c != stop) || /* checked */
+	    (ctxt->input != input))) && (ctxt->instate != XML_PARSER_EOF)) {
 	if (len + 5 >= size) {
 	    xmlChar *tmp;
 
@@ -3560,6 +3590,10 @@ xmlParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
 	}
     }
     buf[len] = 0;
+    if (ctxt->instate == XML_PARSER_EOF) {
+        xmlFree(buf);
+        return(NULL);
+    }
 
     /*
      * Raise problem w.r.t. '&' and '%' being used in non-entities
@@ -3607,12 +3641,12 @@ xmlParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
 	 */
 	ret = xmlStringDecodeEntities(ctxt, buf, XML_SUBSTITUTE_PEREF,
 				      0, 0, 0);
-	if (orig != NULL) 
+	if (orig != NULL)
 	    *orig = buf;
 	else
 	    xmlFree(buf);
     }
-    
+
     return(ret);
 }
 
@@ -3663,8 +3697,9 @@ xmlParseAttValueComplex(xmlParserCtxtPtr ctxt, int *attlen, int normalize) {
      * OK loop until we reach one of the ending char or a size limit.
      */
     c = CUR_CHAR(l);
-    while ((NXT(0) != limit) && /* checked */
-           (IS_CHAR(c)) && (c != '<')) {
+    while (((NXT(0) != limit) && /* checked */
+            (IS_CHAR(c)) && (c != '<')) &&
+            (ctxt->instate != XML_PARSER_EOF)) {
 	if (c == 0) break;
 	if (c == '&') {
 	    in_space = 0;
@@ -3799,6 +3834,9 @@ xmlParseAttValueComplex(xmlParserCtxtPtr ctxt, int *attlen, int normalize) {
 	GROW;
 	c = CUR_CHAR(l);
     }
+    if (ctxt->instate == XML_PARSER_EOF)
+        goto error;
+
     if ((in_space) && (normalize)) {
         while ((len > 0) && (buf[len - 1] == 0x20)) len--;
     }
@@ -3820,6 +3858,7 @@ xmlParseAttValueComplex(xmlParserCtxtPtr ctxt, int *attlen, int normalize) {
 
 mem_error:
     xmlErrMemory(ctxt, NULL);
+error:
     if (buf != NULL)
         xmlFree(buf);
     if (rep != NULL)
@@ -3925,6 +3964,10 @@ xmlParseSystemLiteral(xmlParserCtxtPtr ctxt) {
 	if (count > 50) {
 	    GROW;
 	    count = 0;
+            if (ctxt->instate == XML_PARSER_EOF) {
+	        xmlFree(buf);
+		return(NULL);
+            }
 	}
 	COPY_BUF(l,buf,len,cur);
 	NEXTL(l);
@@ -4002,6 +4045,10 @@ xmlParsePubidLiteral(xmlParserCtxtPtr ctxt) {
 	if (count > 50) {
 	    GROW;
 	    count = 0;
+            if (ctxt->instate == XML_PARSER_EOF) {
+		xmlFree(buf);
+		return(NULL);
+            }
 	}
 	NEXT;
 	cur = CUR;
@@ -4208,6 +4255,8 @@ xmlParseCharData(xmlParserCtxtPtr ctxt, int cdata) {
 	    }
 	    SHRINK;
 	    GROW;
+            if (ctxt->instate == XML_PARSER_EOF)
+		return;
 	    in = ctxt->input->cur;
 	} while (((*in >= 0x20) && (*in <= 0x7F)) || (*in == 0x09));
 	nbchar = 0;
@@ -4276,6 +4325,8 @@ xmlParseCharDataComplex(xmlParserCtxtPtr ctxt, int cdata) {
 	if (count > 50) {
 	    GROW;
 	    count = 0;
+            if (ctxt->instate == XML_PARSER_EOF)
+		return;
 	}
 	NEXTL(l);
 	cur = CUR_CHAR(l);
@@ -4476,6 +4527,10 @@ xmlParseCommentComplex(xmlParserCtxtPtr ctxt, xmlChar *buf, int len, int size) {
 	if (count > 50) {
 	    GROW;
 	    count = 0;
+            if (ctxt->instate == XML_PARSER_EOF) {
+		xmlFree(buf);
+		return;
+            }
 	}
 	NEXTL(l);
 	cur = CUR_CHAR(l);
@@ -4626,6 +4681,10 @@ xmlParseComment(xmlParserCtxtPtr ctxt) {
 	}
 	SHRINK;
 	GROW;
+        if (ctxt->instate == XML_PARSER_EOF) {
+            xmlFree(buf);
+            return;
+	}
 	in = ctxt->input->cur;
 	if (*in == '-') {
 	    if (in[1] == '-') {
@@ -4644,7 +4703,8 @@ xmlParseComment(xmlParserCtxtPtr ctxt) {
 		    }
 		    if (buf != NULL)
 		        xmlFree(buf);
-		    ctxt->instate = state;
+		    if (ctxt->instate != XML_PARSER_EOF)
+			ctxt->instate = state;
 		    return;
 		}
 		if (buf != NULL)
@@ -4862,6 +4922,10 @@ xmlParsePI(xmlParserCtxtPtr ctxt) {
 		count++;
 		if (count > 50) {
 		    GROW;
+                    if (ctxt->instate == XML_PARSER_EOF) {
+                        xmlFree(buf);
+                        return;
+                    }
 		    count = 0;
 		}
 		COPY_BUF(l,buf,len,cur);
@@ -5211,6 +5275,8 @@ xmlParseEntityDecl(xmlParserCtxtPtr ctxt) {
 		}
 	    }
 	}
+	if (ctxt->instate == XML_PARSER_EOF)
+	    return;
 	SKIP_BLANKS;
 	if (RAW != '>') {
 	    xmlFatalErrMsgStr(ctxt, XML_ERR_ENTITY_NOT_FINISHED,
@@ -5602,7 +5668,7 @@ xmlParseAttributeListDecl(xmlParserCtxtPtr ctxt) {
 	}
 	SKIP_BLANKS;
 	GROW;
-	while (RAW != '>') {
+	while ((RAW != '>') && (ctxt->instate != XML_PARSER_EOF)) {
 	    const xmlChar *check = CUR_PTR;
 	    int type;
 	    int def;
@@ -5751,7 +5817,7 @@ xmlParseElementMixedContentDecl(xmlParserCtxtPtr ctxt, int inputchk) {
 	    ret = cur = xmlNewDocElementContent(ctxt->myDoc, NULL, XML_ELEMENT_CONTENT_PCDATA);
 	    if (ret == NULL) return(NULL);
 	}
-	while (RAW == '|') {
+	while ((RAW == '|') && (ctxt->instate != XML_PARSER_EOF)) {
 	    NEXT;
 	    if (elem == NULL) {
 	        ret = xmlNewDocElementContent(ctxt->myDoc, NULL, XML_ELEMENT_CONTENT_OR);
@@ -5895,7 +5961,7 @@ xmlParseElementChildrenContentDeclPriv(xmlParserCtxtPtr ctxt, int inputchk,
     }
     SKIP_BLANKS;
     SHRINK;
-    while (RAW != ')') {
+    while ((RAW != ')') && (ctxt->instate != XML_PARSER_EOF)) {
         /*
 	 * Each loop we parse one separator and one element.
 	 */
@@ -6174,6 +6240,8 @@ xmlParseElementContentDecl(xmlParserCtxtPtr ctxt, const xmlChar *name,
     }
     NEXT;
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(-1);
     SKIP_BLANKS;
     if (CMP7(CUR_PTR, '#', 'P', 'C', 'D', 'A', 'T', 'A')) {
         tree = xmlParseElementMixedContentDecl(ctxt, inputid);
@@ -6341,8 +6409,8 @@ xmlParseConditionalSections(xmlParserCtxtPtr ctxt) {
 		    "Entering INCLUDE Conditional Section\n");
 	}
 
-	while ((RAW != 0) && ((RAW != ']') || (NXT(1) != ']') ||
-	       (NXT(2) != '>'))) {
+	while (((RAW != 0) && ((RAW != ']') || (NXT(1) != ']') ||
+	        (NXT(2) != '>'))) && (ctxt->instate != XML_PARSER_EOF)) {
 	    const xmlChar *check = CUR_PTR;
 	    unsigned int cons = ctxt->input->consumed;
 
@@ -6410,7 +6478,8 @@ xmlParseConditionalSections(xmlParserCtxtPtr ctxt) {
 	if (ctxt->recovery == 0) ctxt->disableSAX = 1;
 	ctxt->instate = XML_PARSER_IGNORE;
 
-	while ((depth >= 0) && (RAW != 0)) {
+	while (((depth >= 0) && (RAW != 0)) &&
+               (ctxt->instate != XML_PARSER_EOF)) {
 	  if ((RAW == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
 	    depth++;
 	    SKIP(3);
@@ -6681,7 +6750,7 @@ xmlParseExternalSubset(xmlParserCtxtPtr ctxt, const xmlChar *ExternalID,
 	    break;
 	}
     }
-    
+
     if (RAW != 0) {
 	xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, NULL);
     }
@@ -7127,6 +7196,8 @@ xmlParseEntityRef(xmlParserCtxtPtr ctxt) {
     xmlEntityPtr ent = NULL;
 
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(NULL);
 
     if (RAW != '&')
         return(NULL);
@@ -7172,6 +7243,8 @@ xmlParseEntityRef(xmlParserCtxtPtr ctxt) {
 	    ent = xmlSAX2GetEntity(ctxt, name);
 	}
     }
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(NULL);
     /*
      * [ WFC: Entity Declared ]
      * In a document without any DTD, a document with only an
@@ -7362,6 +7435,10 @@ xmlParseStringEntityRef(xmlParserCtxtPtr ctxt, const xmlChar ** str) {
 	    ent = xmlSAX2GetEntity(ctxt, name);
 	}
     }
+    if (ctxt->instate == XML_PARSER_EOF) {
+	xmlFree(name);
+	return(NULL);
+    }
 
     /*
      * [ WFC: Entity Declared ]
@@ -7523,8 +7600,9 @@ xmlParsePEReference(xmlParserCtxtPtr ctxt)
      */
     if ((ctxt->sax != NULL) &&
 	(ctxt->sax->getParameterEntity != NULL))
-	entity = ctxt->sax->getParameterEntity(ctxt->userData,
-					       name);
+	entity = ctxt->sax->getParameterEntity(ctxt->userData, name);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return;
     if (entity == NULL) {
 	/*
 	 * [ WFC: Entity Declared ]
@@ -7657,6 +7735,10 @@ xmlLoadEntityContent(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
 	if (count++ > 100) {
 	    count = 0;
 	    GROW;
+            if (ctxt->instate == XML_PARSER_EOF) {
+                xmlBufferFree(buf);
+                return(-1);
+            }
 	}
 	NEXTL(l);
 	c = CUR_CHAR(l);
@@ -7748,8 +7830,11 @@ xmlParseStringPEReference(xmlParserCtxtPtr ctxt, const xmlChar **str) {
      */
     if ((ctxt->sax != NULL) &&
 	(ctxt->sax->getParameterEntity != NULL))
-	entity = ctxt->sax->getParameterEntity(ctxt->userData,
-					       name);
+	entity = ctxt->sax->getParameterEntity(ctxt->userData, name);
+    if (ctxt->instate == XML_PARSER_EOF) {
+	xmlFree(name);
+	return(NULL);
+    }
     if (entity == NULL) {
 	/*
 	 * [ WFC: Entity Declared ]
@@ -7851,6 +7936,8 @@ xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
     if ((ctxt->sax != NULL) && (ctxt->sax->internalSubset != NULL) &&
 	(!ctxt->disableSAX))
 	ctxt->sax->internalSubset(ctxt->userData, name, ExternalID, URI);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return;
 
     /*
      * Is there any internal subset declarations ?
@@ -7890,7 +7977,7 @@ xmlParseInternalSubset(xmlParserCtxtPtr ctxt) {
 	 * PEReferences.
 	 * Subsequence (markupdecl | PEReference | S)*
 	 */
-	while (RAW != ']') {
+	while ((RAW != ']') && (ctxt->instate != XML_PARSER_EOF)) {
 	    const xmlChar *check = CUR_PTR;
 	    unsigned int cons = ctxt->input->consumed;
 
@@ -8076,9 +8163,9 @@ xmlParseStartTag(xmlParserCtxtPtr ctxt) {
     SKIP_BLANKS;
     GROW;
 
-    while ((RAW != '>') && 
+    while (((RAW != '>') && 
 	   ((RAW != '/') || (NXT(1) != '>')) &&
-	   (IS_BYTE_CHAR(RAW))) {
+	   (IS_BYTE_CHAR(RAW))) && (ctxt->instate != XML_PARSER_EOF)) {
 	const xmlChar *q = CUR_PTR;
 	unsigned int cons = ctxt->input->consumed;
 
@@ -8502,6 +8589,8 @@ xmlParseAttValueInternal(xmlParserCtxtPtr ctxt, int *len, int *alloc,
 	    if (in >= end) {
 		const xmlChar *oldbase = ctxt->input->base;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 		if (oldbase != ctxt->input->base) {
 		    long delta = ctxt->input->base - oldbase;
 		    start = start + delta;
@@ -8516,6 +8605,8 @@ xmlParseAttValueInternal(xmlParserCtxtPtr ctxt, int *len, int *alloc,
 	    if (in >= end) {
 		const xmlChar *oldbase = ctxt->input->base;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 		if (oldbase != ctxt->input->base) {
 		    long delta = ctxt->input->base - oldbase;
 		    start = start + delta;
@@ -8536,6 +8627,8 @@ xmlParseAttValueInternal(xmlParserCtxtPtr ctxt, int *len, int *alloc,
 	    if (in >= end) {
 		const xmlChar *oldbase = ctxt->input->base;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 		if (oldbase != ctxt->input->base) {
 		    long delta = ctxt->input->base - oldbase;
 		    start = start + delta;
@@ -8553,6 +8646,8 @@ xmlParseAttValueInternal(xmlParserCtxtPtr ctxt, int *len, int *alloc,
 	    if (in >= end) {
 		const xmlChar *oldbase = ctxt->input->base;
 		GROW;
+                if (ctxt->instate == XML_PARSER_EOF)
+                    return(NULL);
 		if (oldbase != ctxt->input->base) {
 		    long delta = ctxt->input->base - oldbase;
 		    start = start + delta;
@@ -8784,9 +8879,9 @@ xmlParseStartTag2(xmlParserCtxtPtr ctxt, const xmlChar **pref,
     GROW;
     if (ctxt->input->base != base) goto base_changed;
 
-    while ((RAW != '>') && 
+    while (((RAW != '>') && 
 	   ((RAW != '/') || (NXT(1) != '>')) &&
-	   (IS_BYTE_CHAR(RAW))) {
+	   (IS_BYTE_CHAR(RAW))) && (ctxt->instate != XML_PARSER_EOF)) {
 	const xmlChar *q = CUR_PTR;
 	unsigned int cons = ctxt->input->consumed;
 	int len = -1, alloc = 0;
@@ -8957,6 +9052,8 @@ xmlParseStartTag2(xmlParserCtxtPtr ctxt, const xmlChar **pref,
 failed:
 
 	GROW
+        if (ctxt->instate == XML_PARSER_EOF)
+            break;
 	if (ctxt->input->base != base) goto base_changed;
 	if ((RAW == '>') || (((RAW == '/') && (NXT(1) == '>'))))
 	    break;
@@ -9194,6 +9291,8 @@ xmlParseEndTag2(xmlParserCtxtPtr ctxt, const xmlChar *prefix,
      * We should definitely be at the ending "S? '>'" part
      */
     GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return;
     SKIP_BLANKS;
     if ((!IS_BYTE_CHAR(RAW)) || (RAW != '>')) {
 	xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, NULL);
@@ -9302,6 +9401,10 @@ xmlParseCDSect(xmlParserCtxtPtr ctxt) {
 	count++;
 	if (count > 50) {
 	    GROW;
+            if (ctxt->instate == XML_PARSER_EOF) {
+		xmlFree(buf);
+		return;
+            }
 	    count = 0;
 	}
 	NEXTL(l);
@@ -9550,6 +9653,8 @@ xmlParseElement(xmlParserCtxtPtr ctxt) {
      * Parse the content of the element:
      */
     xmlParseContent(ctxt);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return;
     if (!IS_BYTE_CHAR(RAW)) {
         xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_TAG_NOT_FINISHED,
 	 "Premature end of data in tag %s line %d\n",
@@ -10065,9 +10170,10 @@ xmlParseXMLDecl(xmlParserCtxtPtr ctxt) {
 
 void
 xmlParseMisc(xmlParserCtxtPtr ctxt) {
-    while (((RAW == '<') && (NXT(1) == '?')) ||
-           (CMP4(CUR_PTR, '<', '!', '-', '-')) ||
-           IS_BLANK_CH(CUR)) {
+    while ((ctxt->instate != XML_PARSER_EOF) &&
+           (((RAW == '<') && (NXT(1) == '?')) ||
+            (CMP4(CUR_PTR, '<', '!', '-', '-')) ||
+            IS_BLANK_CH(CUR))) {
         if ((RAW == '<') && (NXT(1) == '?')) {
 	    xmlParsePI(ctxt);
 	} else if (IS_BLANK_CH(CUR)) {
@@ -10114,6 +10220,8 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
      */
     if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
         ctxt->sax->setDocumentLocator(ctxt->userData, &xmlDefaultSAXLocator);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(-1);
 
     if ((ctxt->encoding == (const xmlChar *)XML_CHAR_ENCODING_NONE) &&
         ((ctxt->input->end - ctxt->input->cur) >= 4)) {
@@ -10165,6 +10273,8 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
     }
     if ((ctxt->sax) && (ctxt->sax->startDocument) && (!ctxt->disableSAX))
         ctxt->sax->startDocument(ctxt->userData);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(-1);
 
     /*
      * The Misc part of the Prolog
@@ -10184,6 +10294,8 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
 	if (RAW == '[') {
 	    ctxt->instate = XML_PARSER_DTD;
 	    xmlParseInternalSubset(ctxt);
+	    if (ctxt->instate == XML_PARSER_EOF)
+		return(-1);
 	}
 
 	/*
@@ -10194,6 +10306,8 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
 	    (!ctxt->disableSAX))
 	    ctxt->sax->externalSubset(ctxt->userData, ctxt->intSubName,
 	                              ctxt->extSubSystem, ctxt->extSubURI);
+	if (ctxt->instate == XML_PARSER_EOF)
+	    return(-1);
 	ctxt->inSubset = 0;
 
         xmlCleanSpecialAttr(ctxt);
@@ -10334,6 +10448,8 @@ xmlParseExtParsedEnt(xmlParserCtxtPtr ctxt) {
     }
     if ((ctxt->sax) && (ctxt->sax->startDocument) && (!ctxt->disableSAX))
         ctxt->sax->startDocument(ctxt->userData);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(-1);
 
     /*
      * Doing validity checking on chunk doesn't make sense
@@ -10344,6 +10460,8 @@ xmlParseExtParsedEnt(xmlParserCtxtPtr ctxt) {
     ctxt->depth = 0;
 
     xmlParseContent(ctxt);
+    if (ctxt->instate == XML_PARSER_EOF)
+	return(-1);
    
     if ((RAW == '<') && (NXT(1) == '/')) {
 	xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, NULL);
@@ -10651,7 +10769,7 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
     }
     xmlParseGetLasts(ctxt, &lastlt, &lastgt);
 
-    while (1) {
+    while (ctxt->instate != XML_PARSER_EOF) {
 	if ((ctxt->errNo != XML_ERR_OK) && (ctxt->disableSAX == 1))
 	    return(0);
 
@@ -10891,6 +11009,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    ctxt->sax->endElement(ctxt->userData, name);
 #endif /* LIBXML_SAX1_ENABLED */
 		    }
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    spacePop(ctxt);
 		    if (ctxt->nameNr == 0) {
 			ctxt->instate = XML_PARSER_EPILOG;
@@ -11072,6 +11192,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 				ctxt->sax->characters(ctxt->userData,
 				                      ctxt->input->cur, tmp);
 			}
+			if (ctxt->instate == XML_PARSER_EOF)
+			    goto done;
 			SKIPL(tmp);
 			ctxt->checkIndex = 0;
 		    }
@@ -11107,6 +11229,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    ctxt->sax->characters(ctxt->userData,
 						  ctxt->input->cur, base);
 		    }
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    SKIPL(base + 3);
 		    ctxt->checkIndex = 0;
 		    ctxt->instate = XML_PARSER_CONTENT;
@@ -11138,6 +11262,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing PI\n");
 #endif
 		    xmlParsePI(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    ctxt->checkIndex = 0;
 		} else if ((cur == '<') && (next == '!') &&
 		    (ctxt->input->cur[2] == '-') &&
@@ -11150,6 +11276,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing Comment\n");
 #endif
 		    xmlParseComment(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    ctxt->instate = XML_PARSER_MISC;
 		    ctxt->checkIndex = 0;
 		} else if ((cur == '<') && (next == '!') &&
@@ -11169,6 +11297,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 #endif
 		    ctxt->inSubset = 1;
 		    xmlParseDocTypeDecl(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    if (RAW == '[') {
 			ctxt->instate = XML_PARSER_DTD;
 #ifdef DEBUG_PUSH
@@ -11225,6 +11355,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing PI\n");
 #endif
 		    xmlParsePI(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		} else if ((cur == '<') && (next == '!') &&
 		    (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
 		    if ((!terminate) &&
@@ -11235,6 +11367,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing Comment\n");
 #endif
 		    xmlParseComment(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    ctxt->instate = XML_PARSER_PROLOG;
 		} else if ((cur == '<') && (next == '!') &&
 		           (avail < 4)) {
@@ -11269,6 +11403,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing PI\n");
 #endif
 		    xmlParsePI(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    ctxt->instate = XML_PARSER_EPILOG;
 		} else if ((cur == '<') && (next == '!') &&
 		    (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
@@ -11280,6 +11416,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 			    "PP: Parsing Comment\n");
 #endif
 		    xmlParseComment(ctxt);
+		    if (ctxt->instate == XML_PARSER_EOF)
+			goto done;
 		    ctxt->instate = XML_PARSER_EPILOG;
 		} else if ((cur == '<') && (next == '!') &&
 		           (avail < 4)) {
@@ -11408,13 +11546,17 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
 
 found_end_int_subset:
 		xmlParseInternalSubset(ctxt);
+		if (ctxt->instate == XML_PARSER_EOF)
+		    goto done;
 		ctxt->inSubset = 2;
 		if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
 		    (ctxt->sax->externalSubset != NULL))
 		    ctxt->sax->externalSubset(ctxt->userData, ctxt->intSubName,
 			    ctxt->extSubSystem, ctxt->extSubURI);
 		ctxt->inSubset = 0;
 		xmlCleanSpecialAttr(ctxt);
+		if (ctxt->instate == XML_PARSER_EOF)
+		    goto done;
 		ctxt->instate = XML_PARSER_PROLOG;
 		ctxt->checkIndex = 0;
 #ifdef DEBUG_PUSH
@@ -11537,6 +11679,8 @@ xmlParseChunk(xmlParserCtxtPtr ctxt, const char *chunk, int size,
         return(XML_ERR_INTERNAL_ERROR);
     if ((ctxt->errNo != XML_ERR_OK) && (ctxt->disableSAX == 1))
         return(ctxt->errNo);
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(-1);
     if (ctxt->instate == XML_PARSER_START)
         xmlDetectSAX2(ctxt);
     if ((size > 0) && (chunk != NULL) && (!terminate) &&
@@ -11623,6 +11767,8 @@ xmlParseChunk(xmlParserCtxtPtr ctxt, const char *chunk, int size,
         xmlParseTryOrFinish(ctxt, 0);
     else
         xmlParseTryOrFinish(ctxt, terminate);
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(ctxt->errNo);
     if ((ctxt->errNo != XML_ERR_OK) && (ctxt->disableSAX == 1))
         return(ctxt->errNo);
 
@@ -11816,6 +11962,7 @@ xmlStopParser(xmlParserCtxtPtr ctxt) {
     if (ctxt == NULL)
         return;
     ctxt->instate = XML_PARSER_EOF;
+    ctxt->errNo = XML_ERR_USER_STOP;
     ctxt->disableSAX = 1;
     if (ctxt->input != NULL) {
 	ctxt->input->cur = BAD_CAST"";
```


### `third_party/libxml/README.chromium`

```diff
@@ -35,6 +35,7 @@ if treated as a generic xmlNode object.
 - Import attribute normalization fix http://git.gnome.org/browse/libxml2/commit/?id=6a36fbe3b3e001a8a840b5c1fdd81cefc9947f0d
 - Merge a redundant comparison fix http://git.gnome.org/browse/libxml2/commit/?id=2af19f985b911b6dc6ada478ba8d201d2ddc9309
 - Merge a redundant comparisons fix https://git.gnome.org/browse/libxml2/commit/?id=eea38159be421dbafbee38f40e239f91734bc713
+- Merge XML_PARSER_EOF checks https://git.gnome.org/browse/libxml2/commit/?id=48b4cdde3483e054af8ea02e0cd7ee467b0e9a50 and https://git.gnome.org/browse/libxml2/commit/?id=e50ba8164eee06461c73cd8abb9b46aa0be81869
 
 To import a new snapshot of libxml:
 
```


### `third_party/libxml/src/include/libxml/xmlerror.h`

```diff
@@ -205,6 +205,7 @@ typedef enum {
     XML_WAR_ENTITY_REDEFINED, /* 107 */
     XML_ERR_UNKNOWN_VERSION, /* 108 */
     XML_ERR_VERSION_MISMATCH, /* 109 */
+    XML_ERR_USER_STOP, /* 110 */
     XML_NS_ERR_XML_NAMESPACE = 200,
     XML_NS_ERR_UNDEFINED_NAMESPACE, /* 201 */
     XML_NS_ERR_QNAME, /* 202 */
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
