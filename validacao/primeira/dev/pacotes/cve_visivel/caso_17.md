# Pacote de anotacao — caso 17

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

# Evidencia do caso 17

## Identificacao

- projeto: tcpdump
- CVE: CVE-2017-13050
- CWE atribuida pelo BigVul: CWE-125
- commit: `83c64fce3a5226b080e535f5131a8a318f30e79b`
- URL do commit: https://github.com/the-tcpdump-group/tcpdump/commit/83c64fce3a5226b080e535f5131a8a318f30e79b
- arquivo da funcao marcada: `print-rpki-rtr.c`

## Mensagem do commit

> CVE-2017-13050/RPKI-Router: fix a few bugs
> 
> The decoder didn't properly check that the PDU length stored in the PDU
> header is correct. The only check in place was in rpki_rtr_print() and it
> tested whether the length is zero but that is not sufficient. Make all
> necessary length and bounds checks, both generic and type-specific, in
> rpki_rtr_pdu_print() and reduce rpki_rtr_print() to a simple loop.
> 
> This also fixes a minor bug and PDU type 0 (Serial Notify from RFC 6810
> Section 5.2) is valid again.
> 
> In rpki_rtr_pdu_print() any protocol version was considered version 0,
> fix it to skip the rest of input if the PDU protocol version is unknown.
> 
> Ibid, the PDU type 10 (Error Report from RFC 6810 Section 5.10) case
> block didn't consider the "Length of Error Text" data element mandatory,
> put it right.
> 
> Ibid, when printing an encapsulated PDU, give itself (via recursion)
> respective buffer length to make it possible to tell whether the
> encapsulated PDU fits. Do not recurse deeper than 2nd level.
> 
> Update prior RPKI-Router test cases that now stop to decode earlier
> because of the stricter checks.
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s).

## Resumo da CVE

> The RPKI-Router parser in tcpdump before 4.9.2 has a buffer over-read in print-rpki-rtr.c:rpki_rtr_pdu_print().

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,36 +1,12 @@
  rpki_rtr_print(netdissect_options *ndo, register const u_char *pptr, register u_int len)
  {
-    u_int tlen, pdu_type, pdu_len;
-    const u_char *tptr;
-    const rpki_rtr_pdu *pdu_header;
-    tptr = pptr;
-    tlen = len;
      if (!ndo->ndo_vflag) {
  	ND_PRINT((ndo, ", RPKI-RTR"));
  	return;
      }
-    while (tlen >= sizeof(rpki_rtr_pdu)) {
-        ND_TCHECK2(*tptr, sizeof(rpki_rtr_pdu));
-	pdu_header = (const rpki_rtr_pdu *)tptr;
-        pdu_type = pdu_header->pdu_type;
-        pdu_len = EXTRACT_32BITS(pdu_header->length);
-        ND_TCHECK2(*tptr, pdu_len);
-        /* infinite loop check */
-        if (!pdu_type || !pdu_len) {
-            break;
-        }
-        if (tlen < pdu_len) {
-            goto trunc;
-        }
-	/*
-	 * Print the PDU.
-	 */
-	if (rpki_rtr_pdu_print(ndo, tptr, 8))
-		goto trunc;
-        tlen -= pdu_len;
-        tptr += pdu_len;
+    while (len) {
+	u_int pdu_len = rpki_rtr_pdu_print(ndo, pptr, len, 1, 8);
+	len -= pdu_len;
+	pptr += pdu_len;
      }
-    return;
-trunc:
-    ND_PRINT((ndo, "\n\t%s", tstr));
  }
```

## Corpo completo da funcao antes da correcao

```c
 rpki_rtr_print(netdissect_options *ndo, register const u_char *pptr, register u_int len)
 {
    u_int tlen, pdu_type, pdu_len;
    const u_char *tptr;
    const rpki_rtr_pdu *pdu_header;
    tptr = pptr;
    tlen = len;
     if (!ndo->ndo_vflag) {
 	ND_PRINT((ndo, ", RPKI-RTR"));
 	return;
     }
    while (tlen >= sizeof(rpki_rtr_pdu)) {
        ND_TCHECK2(*tptr, sizeof(rpki_rtr_pdu));
	pdu_header = (const rpki_rtr_pdu *)tptr;
        pdu_type = pdu_header->pdu_type;
        pdu_len = EXTRACT_32BITS(pdu_header->length);
        ND_TCHECK2(*tptr, pdu_len);
        /* infinite loop check */
        if (!pdu_type || !pdu_len) {
            break;
        }
        if (tlen < pdu_len) {
            goto trunc;
        }
	/*
	 * Print the PDU.
	 */
	if (rpki_rtr_pdu_print(ndo, tptr, 8))
		goto trunc;
        tlen -= pdu_len;
        tptr += pdu_len;
     }
    return;
trunc:
    ND_PRINT((ndo, "\n\t%s", tstr));
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **10**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-rpki-rtr.c` **(funcao marcada esta aqui)** | modified | 103 | 66 |
| `tests/TESTLIST` | modified | 1 | 0 |
| `tests/kday2.out` | modified | 1 | 8 |
| `tests/kday3.out` | modified | 2 | 16 |
| `tests/kday4.out` | modified | 3 | 28 |
| `tests/kday5.out` | modified | 1 | 9 |
| `tests/kday7.out` | modified | 3 | 26 |
| `tests/kday8.out` | modified | 1 | 8 |
| `tests/rpki-rtr-oob.out` | added | 3 | 0 |
| `tests/rpki-rtr-oob.pcap` | added | 0 | 0 |


### `print-rpki-rtr.c`

```diff
@@ -82,6 +82,9 @@ typedef struct rpki_rtr_pdu_ipv6_prefix_ {
 typedef struct rpki_rtr_pdu_error_report_ {
     rpki_rtr_pdu pdu_header;
     u_char encapsulated_pdu_length[4]; /* Encapsulated PDU length */
+    /* Copy of Erroneous PDU (variable, optional) */
+    /* Length of Error Text (4 octets in network byte order) */
+    /* Arbitrary Text of Error Diagnostic Message (variable, optional) */
 } rpki_rtr_pdu_error_report;
 
 /*
@@ -171,24 +174,47 @@ indent_string (u_int indent)
 /*
  * Print a single PDU.
  */
-static int
-rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
+static u_int
+rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, const u_int len,
+	const u_char recurse, const u_int indent)
 {
     const rpki_rtr_pdu *pdu_header;
     u_int pdu_type, pdu_len, hexdump;
     const u_char *msg;
 
+    /* Protocol Version */
+    ND_TCHECK_8BITS(tptr);
+    if (*tptr != 0) {
+	/* Skip the rest of the input buffer because even if this is
+	 * a well-formed PDU of a future RPKI-Router protocol version
+	 * followed by a well-formed PDU of RPKI-Router protocol
+	 * version 0, there is no way to know exactly how to skip the
+	 * current PDU.
+	 */
+	ND_PRINT((ndo, "%sRPKI-RTRv%u (unknown)", indent_string(8), *tptr));
+	return len;
+    }
+    if (len < sizeof(rpki_rtr_pdu)) {
+	ND_PRINT((ndo, "(%u bytes is too few to decode)", len));
+	goto invalid;
+    }
+    ND_TCHECK2(*tptr, sizeof(rpki_rtr_pdu));
     pdu_header = (const rpki_rtr_pdu *)tptr;
     pdu_type = pdu_header->pdu_type;
     pdu_len = EXTRACT_32BITS(pdu_header->length);
-    ND_TCHECK2(*tptr, pdu_len);
+    /* Do not check bounds with pdu_len yet, do it in the case blocks
+     * below to make it possible to decode at least the beginning of
+     * a truncated Error Report PDU or a truncated encapsulated PDU.
+     */
     hexdump = FALSE;
 
     ND_PRINT((ndo, "%sRPKI-RTRv%u, %s PDU (%u), length: %u",
 	   indent_string(8),
 	   pdu_header->version,
 	   tok2str(rpki_rtr_pdu_values, "Unknown", pdu_type),
 	   pdu_type, pdu_len));
+    if (pdu_len < sizeof(rpki_rtr_pdu) || pdu_len > len)
+	goto invalid;
 
     switch (pdu_type) {
 
@@ -198,6 +224,9 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
     case RPKI_RTR_SERIAL_NOTIFY_PDU:
     case RPKI_RTR_SERIAL_QUERY_PDU:
     case RPKI_RTR_END_OF_DATA_PDU:
+	if (pdu_len != sizeof(rpki_rtr_pdu) + 4)
+	    goto invalid;
+	ND_TCHECK2(*tptr, pdu_len);
         msg = (const u_char *)(pdu_header + 1);
 	ND_PRINT((ndo, "%sSession ID: 0x%04x, Serial: %u",
 	       indent_string(indent+2),
@@ -210,13 +239,19 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
 	 */
     case RPKI_RTR_RESET_QUERY_PDU:
     case RPKI_RTR_CACHE_RESET_PDU:
+	if (pdu_len != sizeof(rpki_rtr_pdu))
+	    goto invalid;
+	/* no additional boundary to check */
 
 	/*
 	 * Zero payload PDUs.
 	 */
 	break;
 
     case RPKI_RTR_CACHE_RESPONSE_PDU:
+	if (pdu_len != sizeof(rpki_rtr_pdu))
+	    goto invalid;
+	/* no additional boundary to check */
 	ND_PRINT((ndo, "%sSession ID: 0x%04x",
 	       indent_string(indent+2),
 	       EXTRACT_16BITS(pdu_header->u.session_id)));
@@ -226,6 +261,9 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
 	{
 	    const rpki_rtr_pdu_ipv4_prefix *pdu;
 
+	    if (pdu_len != sizeof(rpki_rtr_pdu) + 12)
+		goto invalid;
+	    ND_TCHECK2(*tptr, pdu_len);
 	    pdu = (const rpki_rtr_pdu_ipv4_prefix *)tptr;
 	    ND_PRINT((ndo, "%sIPv4 Prefix %s/%u-%u, origin-as %u, flags 0x%02x",
 		   indent_string(indent+2),
@@ -239,6 +277,9 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
 	{
 	    const rpki_rtr_pdu_ipv6_prefix *pdu;
 
+	    if (pdu_len != sizeof(rpki_rtr_pdu) + 24)
+		goto invalid;
+	    ND_TCHECK2(*tptr, pdu_len);
 	    pdu = (const rpki_rtr_pdu_ipv6_prefix *)tptr;
 	    ND_PRINT((ndo, "%sIPv6 Prefix %s/%u-%u, origin-as %u, flags 0x%02x",
 		   indent_string(indent+2),
@@ -253,52 +294,76 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
 	    const rpki_rtr_pdu_error_report *pdu;
 	    u_int encapsulated_pdu_length, text_length, tlen, error_code;
 
+	    tlen = sizeof(rpki_rtr_pdu);
+	    /* Do not test for the "Length of Error Text" data element yet. */
+	    if (pdu_len < tlen + 4)
+		goto invalid;
+	    ND_TCHECK2(*tptr, tlen + 4);
+	    /* Safe up to and including the "Length of Encapsulated PDU"
+	     * data element, more data elements may be present.
+	     */
 	    pdu = (const rpki_rtr_pdu_error_report *)tptr;
 	    encapsulated_pdu_length = EXTRACT_32BITS(pdu->encapsulated_pdu_length);
-	    ND_TCHECK2(*tptr, encapsulated_pdu_length);
-	    tlen = pdu_len;
+	    tlen += 4;
 
 	    error_code = EXTRACT_16BITS(pdu->pdu_header.u.error_code);
 	    ND_PRINT((ndo, "%sError code: %s (%u), Encapsulated PDU length: %u",
 		   indent_string(indent+2),
 		   tok2str(rpki_rtr_error_codes, "Unknown", error_code),
 		   error_code, encapsulated_pdu_length));
 
-	    tptr += sizeof(*pdu);
-	    tlen -= sizeof(*pdu);
-
-	    /*
-	     * Recurse if there is an encapsulated PDU.
-	     */
-	    if (encapsulated_pdu_length &&
-		(encapsulated_pdu_length <= tlen)) {
-		ND_PRINT((ndo, "%s-----encapsulated PDU-----", indent_string(indent+4)));
-		if (rpki_rtr_pdu_print(ndo, tptr, indent+2))
-			goto trunc;
+	    if (encapsulated_pdu_length) {
+		/* Section 5.10 of RFC 6810 says:
+		 * "An Error Report PDU MUST NOT be sent for an Error Report PDU."
+		 *
+		 * However, as far as the protocol encoding goes Error Report PDUs can
+		 * happen to be nested in each other, however many times, in which case
+		 * the decoder should still print such semantically incorrect PDUs.
+		 *
+		 * That said, "the Erroneous PDU field MAY be truncated" (ibid), thus
+		 * to keep things simple this implementation decodes only the two
+		 * outermost layers of PDUs and makes bounds checks in the outer and
+		 * the inner PDU independently.
+		 */
+		if (pdu_len < tlen + encapsulated_pdu_length)
+		    goto invalid;
+		if (! recurse) {
+		    ND_TCHECK2(*tptr, tlen + encapsulated_pdu_length);
+		}
+		else {
+		    ND_PRINT((ndo, "%s-----encapsulated PDU-----", indent_string(indent+4)));
+		    rpki_rtr_pdu_print(ndo, tptr + tlen,
+			encapsulated_pdu_length, 0, indent + 2);
+		}
+		tlen += encapsulated_pdu_length;
 	    }
 
-	    tptr += encapsulated_pdu_length;
-	    tlen -= encapsulated_pdu_length;
+	    if (pdu_len < tlen + 4)
+		goto invalid;
+	    ND_TCHECK2(*tptr, tlen + 4);
+	    /* Safe up to and including the "Length of Error Text" data element,
+	     * one more data element may be present.
+	     */
 
 	    /*
 	     * Extract, trail-zero and print the Error message.
 	     */
-	    text_length = 0;
-	    if (tlen > 4) {
-		text_length = EXTRACT_32BITS(tptr);
-		tptr += 4;
-		tlen -= 4;
-	    }
-	    ND_TCHECK2(*tptr, text_length);
-	    if (text_length && (text_length <= tlen )) {
+	    text_length = EXTRACT_32BITS(tptr + tlen);
+	    tlen += 4;
+
+	    if (text_length) {
+		if (pdu_len < tlen + text_length)
+		    goto invalid;
+		/* fn_printn() makes the bounds check */
 		ND_PRINT((ndo, "%sError text: ", indent_string(indent+2)));
-		if (fn_printn(ndo, tptr, text_length, ndo->ndo_snapend))
+		if (fn_printn(ndo, tptr + tlen, text_length, ndo->ndo_snapend))
 			goto trunc;
 	    }
 	}
 	break;
 
     default:
+	ND_TCHECK2(*tptr, pdu_len);
 
 	/*
 	 * Unknown data, please hexdump.
@@ -310,57 +375,29 @@ rpki_rtr_pdu_print (netdissect_options *ndo, const u_char *tptr, u_int indent)
     if (ndo->ndo_vflag > 1 || (ndo->ndo_vflag && hexdump)) {
 	print_unknown_data(ndo,tptr,"\n\t  ", pdu_len);
     }
-    return 0;
+    return pdu_len;
 
+invalid:
+    ND_PRINT((ndo, "%s", istr));
+    ND_TCHECK2(*tptr, len);
+    return len;
 trunc:
-    return 1;
+    ND_PRINT((ndo, "\n\t%s", tstr));
+    return len;
 }
 
 void
 rpki_rtr_print(netdissect_options *ndo, register const u_char *pptr, register u_int len)
 {
-    u_int tlen, pdu_type, pdu_len;
-    const u_char *tptr;
-    const rpki_rtr_pdu *pdu_header;
-
-    tptr = pptr;
-    tlen = len;
-
     if (!ndo->ndo_vflag) {
 	ND_PRINT((ndo, ", RPKI-RTR"));
 	return;
     }
-
-    while (tlen >= sizeof(rpki_rtr_pdu)) {
-
-        ND_TCHECK2(*tptr, sizeof(rpki_rtr_pdu));
-
-	pdu_header = (const rpki_rtr_pdu *)tptr;
-        pdu_type = pdu_header->pdu_type;
-        pdu_len = EXTRACT_32BITS(pdu_header->length);
-        ND_TCHECK2(*tptr, pdu_len);
-
-        /* infinite loop check */
-        if (!pdu_type || !pdu_len) {
-            break;
-        }
-
-        if (tlen < pdu_len) {
-            goto trunc;
-        }
-
-	/*
-	 * Print the PDU.
-	 */
-	if (rpki_rtr_pdu_print(ndo, tptr, 8))
-		goto trunc;
-
-        tlen -= pdu_len;
-        tptr += pdu_len;
+    while (len) {
+	u_int pdu_len = rpki_rtr_pdu_print(ndo, pptr, len, 1, 8);
+	len -= pdu_len;
+	pptr += pdu_len;
     }
-    return;
-trunc:
-    ND_PRINT((ndo, "\n\t%s", tstr));
 }
 
 /*
```


### `tests/TESTLIST`

```diff
@@ -570,6 +570,7 @@ esis_opt_prot-oobr	esis_opt_prot-oobr.pcap		esis_opt_prot-oobr.out	-v -c1
 rsvp_uni-oobr-1	rsvp_uni-oobr-1.pcap	rsvp_uni-oobr-1.out	-v -c1
 rsvp_uni-oobr-2	rsvp_uni-oobr-2.pcap	rsvp_uni-oobr-2.out	-v -c1
 rsvp_uni-oobr-3	rsvp_uni-oobr-3.pcap	rsvp_uni-oobr-3.out	-v -c3
+rpki-rtr-oob		rpki-rtr-oob.pcap	rpki-rtr-oob.out	-v -c1
 
 # bad packets from Katie Holly
 mlppp-oobr		mlppp-oobr.pcap			mlppp-oobr.out
```


### `tests/kday2.out`

```diff
@@ -18,12 +18,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x7767), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x8900), seq 3589495407:3589495754, ack 370428050, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 21
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/kday3.out`

```diff
@@ -7,13 +7,7 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x7767), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x0cf1), seq 3589495407:3589495754, ack 370428050, win 1040, options [nop,nop,TS val 2381534627 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 IP (tos 0x10, ttl 62, id 64806, offset 0, flags [DF], proto TCP (6), length 52)
     204.9.51.132.50079 > 204.9.54.80.22: Flags [.], cksum 0x8611 (incorrect -> 0xa678), ack 0, win 4094, options [nop,nop,TS val 941371775 ecr 4294967242], length 0
 IP (tos 0x10, ttl 62, id 62920, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 4504 (->451a)!)
@@ -22,13 +16,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x8d67), ack 1, win 1040, options [nop,nop,TS val 647770294 ecr 2364773722], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xa6b3), seq 0:347, ack 1, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	    -----encapsulated PDU-----
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/kday4.out`

```diff
@@ -11,15 +11,7 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52)
     204.9.54.80.55936 > 204.9.55.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x725a), ack 3589495407, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xcd5f), seq 3589495407:3589495754, ack 370436242, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 58f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	    -----encapsulated PDU-----
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 IP (tos 0x10, ttl 62, id 64806, offset 0, flags [DF], proto TCP (6), length 52)
     204.9.51.132.50079 > 204.9.54.80.22: Flags [.], cksum 0x8611 (incorrect -> 0xa678), ack 1819218606, win 4094, options [nop,nop,TS val 941371775 ecr 4294967242], length 0
 IP (tos 0x10, ttl 62, id 62920, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 4504 (->451a)!)
@@ -28,15 +20,7 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x8d67), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364773722], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xfa70), seq 0:347, ack 4294959105, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv197, Unknown PDU (100), length: 60
-	  0x0000:  c564 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	    -----encapsulated PDU-----
-	[|RPKI-RTR]
+	RPKI-RTRv197 (unknown)
 IP truncated-ip - 768 bytes missing! (tos 0x10, ttl 62, id 64806, offset 0, flags [DF], proto TCP (6), length 820, bad cksum 3da6 (->3aa6)!)
     204.9.51.132.50079 > 204.9.54.80.22: Flags [.], seq 0:768, ack 1, win 4094, options [nop,nop,TS val 941371775 ecr 4294967242], length 768
 IP (tos 0x6,ECT(0), ttl 62, id 62920, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 4504 (->4524)!)
@@ -45,14 +29,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x8d67), ack 1, win 1040, options [nop,nop,TS val 647770294 ecr 2364773722], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x3f28), seq 0:347, ack 4294959105, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 100
-	  Error text: ^@^@^@M-^?M-^?^_^[pM-xWM-nhMM-}M_M-YM-=M-G^I0M-,M-^AvM-3mM-L^Q:M-?^RM-^QM-q^FNM-^aM-tbM-^WM-/M-D9M-$^MM-9zM-%hs3M-hA^J^@B^@^@^@B^@^@^@%M-Dz^HM-i^RM-^DM-5M-^\M->0H^H^@E^P^@4M-}&@^@>^F
-	RPKI-RTRv115, Error Report PDU (10), length: 66
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/kday5.out`

```diff
@@ -18,13 +18,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x7767), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x183a), seq 3589495407:3589495754, ack 370428050, win 1040, options [nop,nop,TS val 2351322531 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 80
-	  Error text: M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-CM-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9M-9^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^V^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J^J
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/kday7.out`

```diff
@@ -11,15 +11,7 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52)
     204.9.54.80.55936 > 204.9.55.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x725a), ack 3589495407, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xcd5f), seq 3589495407:3589495754, ack 370436242, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 58f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	    -----encapsulated PDU-----
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 IP (tos 0x10, ttl 62, id 64806, offset 0, flags [DF], proto TCP (6), length 52)
     204.9.51.132.50079 > 204.9.54.80.22: Flags [.], cksum 0x8611 (incorrect -> 0xa678), ack 1819218606, win 4094, options [nop,nop,TS val 941371775 ecr 4294967242], length 0
 IP (tos 0x10, ttl 62, id 62920, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 4504 (->451a)!)
@@ -28,15 +20,7 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x8d67), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364773722], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xfa86), seq 0:347, ack 4294959105, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv197, Unknown PDU (100), length: 60
-	  0x0000:  c564 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 37
-	    -----encapsulated PDU-----
-	[|RPKI-RTR]
+	RPKI-RTRv197 (unknown)
 IP truncated-ip - 768 bytes missing! (tos 0x10, ttl 62, id 64806, offset 0, flags [DF], proto TCP (6), length 820, bad cksum 3da6 (->3aa6)!)
     204.9.51.132.50079 > 204.9.54.80.22: Flags [.], seq 0:768, ack 1, win 4094, options [nop,nop,TS val 941371775 ecr 4294967242], length 768
 IP (tos 0x6,ECT(0), ttl 62, id 62920, offset 0, flags [DF], proto TCP (6), length 52, bad cksum 4504 (->4524)!)
@@ -45,12 +29,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x8d67), ack 1, win 1040, options [nop,nop,TS val 647770294 ecr 2364773722], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x4ba9), seq 0:347, ack 4294959105, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 100
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/kday8.out`

```diff
@@ -18,12 +18,5 @@ IP (tos 0x0, ttl 64, id 63178, offset 0, flags [DF], proto TCP (6), length 52, b
     204.9.64.80.55936 > 204.9.40.10.443: Flags [.], cksum 0x0594 (incorrect -> 0x7767), ack 3587398274, win 1040, options [nop,nop,TS val 647770294 ecr 2364779354], length 0
 IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
     204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0xed9b), seq 3589495407:3589495754, ack 370428050, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
-	RPKI-RTRv177, Unknown PDU (100), length: 60
-	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
-	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
-	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
-	  0x0030:  afc4 39a4 0db9 7aa5 6873 33e8
-	RPKI-RTRv65, Error Report PDU (10), length: 66
-	  Error code: Unknown (66), Encapsulated PDU length: 80
-	[|RPKI-RTR]
+	RPKI-RTRv177 (unknown)
 EXIT CODE 00000100
```


### `tests/rpki-rtr-oob.out`

```diff
@@ -0,0 +1,3 @@
+IP truncated-ip - 22 bytes missing! (tos 0x0, ttl 254, id 13327, offset 0, flags [+, DF, rsvd], proto TCP (6), length 62, bad cksum 8e7f (->c283)!)
+    19.128.128.20.323 > 76.19.6.127.49600: Flags [none], seq 2684354563:2684354585, win 28672, length 22
+	RPKI-RTRv171 (unknown)
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
