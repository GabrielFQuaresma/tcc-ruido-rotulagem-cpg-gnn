# Pacote de anotacao — caso 14

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

# Evidencia do caso 14

## Identificacao

- projeto: tcpdump
- CVE: CVE-2017-13039
- CWE atribuida pelo BigVul: CWE-125
- commit: `e0a5a02b0fc1900a69d6c37ed0aab36fb8494e6d`
- URL do commit: https://github.com/the-tcpdump-group/tcpdump/commit/e0a5a02b0fc1900a69d6c37ed0aab36fb8494e6d
- arquivo da funcao marcada: `print-isakmp.c`

## Mensagem do commit

> CVE-2017-13039/IKEv1: Do more bounds checking.
> 
> Have ikev1_attrmap_print() and ikev1_attr_print() do full bounds
> checking, and return null on a bounds overflow.  Have their callers
> check for a null return.
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s), modified
> so the capture file won't be rejected as an invalid capture.

## Resumo da CVE

> The ISAKMP parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c, several functions.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -110,8 +110,11 @@
  			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
  			ND_PRINT((ndo," attrs=("));
  			while (cp < ep && cp < ep2) {
-				cp = ikev1_attrmap_print(ndo, cp,
-					(ep < ep2) ? ep : ep2, map, nmap);
+				cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
+				if (cp == NULL) {
+					ND_PRINT((ndo,")"));
+					goto trunc;
+				}
  			}
  			ND_PRINT((ndo,")"));
  			break;
```

## Corpo completo da funcao antes da correcao

```c
ikev1_n_print(netdissect_options *ndo, u_char tpay _U_,
	      const struct isakmp_gen *ext, u_int item_len,
	      const u_char *ep, uint32_t phase _U_, uint32_t doi0 _U_,
	      uint32_t proto0 _U_, int depth _U_)
{
	const struct ikev1_pl_n *p;
	struct ikev1_pl_n n;
	const u_char *cp;
	const u_char *ep2;
	uint32_t doi;
	uint32_t proto;
	static const char *notify_error_str[] = {
		NULL,				"INVALID-PAYLOAD-TYPE",
		"DOI-NOT-SUPPORTED",		"SITUATION-NOT-SUPPORTED",
		"INVALID-COOKIE",		"INVALID-MAJOR-VERSION",
		"INVALID-MINOR-VERSION",	"INVALID-EXCHANGE-TYPE",
		"INVALID-FLAGS",		"INVALID-MESSAGE-ID",
		"INVALID-PROTOCOL-ID",		"INVALID-SPI",
		"INVALID-TRANSFORM-ID",		"ATTRIBUTES-NOT-SUPPORTED",
		"NO-PROPOSAL-CHOSEN",		"BAD-PROPOSAL-SYNTAX",
		"PAYLOAD-MALFORMED",		"INVALID-KEY-INFORMATION",
		"INVALID-ID-INFORMATION",	"INVALID-CERT-ENCODING",
		"INVALID-CERTIFICATE",		"CERT-TYPE-UNSUPPORTED",
		"INVALID-CERT-AUTHORITY",	"INVALID-HASH-INFORMATION",
		"AUTHENTICATION-FAILED",	"INVALID-SIGNATURE",
		"ADDRESS-NOTIFICATION",		"NOTIFY-SA-LIFETIME",
		"CERTIFICATE-UNAVAILABLE",	"UNSUPPORTED-EXCHANGE-TYPE",
		"UNEQUAL-PAYLOAD-LENGTHS",
	};
	static const char *ipsec_notify_error_str[] = {
		"RESERVED",
	};
	static const char *notify_status_str[] = {
		"CONNECTED",
	};
	static const char *ipsec_notify_status_str[] = {
		"RESPONDER-LIFETIME",		"REPLAY-STATUS",
		"INITIAL-CONTACT",
	};
/* NOTE: these macro must be called with x in proper range */

/* 0 - 8191 */
#define NOTIFY_ERROR_STR(x) \
	STR_OR_ID((x), notify_error_str)

/* 8192 - 16383 */
#define IPSEC_NOTIFY_ERROR_STR(x) \
	STR_OR_ID((u_int)((x) - 8192), ipsec_notify_error_str)

/* 16384 - 24575 */
#define NOTIFY_STATUS_STR(x) \
	STR_OR_ID((u_int)((x) - 16384), notify_status_str)

/* 24576 - 32767 */
#define IPSEC_NOTIFY_STATUS_STR(x) \
	STR_OR_ID((u_int)((x) - 24576), ipsec_notify_status_str)

	ND_PRINT((ndo,"%s:", NPSTR(ISAKMP_NPTYPE_N)));

	p = (const struct ikev1_pl_n *)ext;
	ND_TCHECK(*p);
	UNALIGNED_MEMCPY(&n, ext, sizeof(n));
	doi = ntohl(n.doi);
	proto = n.prot_id;
	if (doi != 1) {
		ND_PRINT((ndo," doi=%d", doi));
		ND_PRINT((ndo," proto=%d", proto));
		if (ntohs(n.type) < 8192)
			ND_PRINT((ndo," type=%s", NOTIFY_ERROR_STR(ntohs(n.type))));
		else if (ntohs(n.type) < 16384)
			ND_PRINT((ndo," type=%s", numstr(ntohs(n.type))));
		else if (ntohs(n.type) < 24576)
			ND_PRINT((ndo," type=%s", NOTIFY_STATUS_STR(ntohs(n.type))));
		else
			ND_PRINT((ndo," type=%s", numstr(ntohs(n.type))));
		if (n.spi_size) {
			ND_PRINT((ndo," spi="));
			if (!rawprint(ndo, (const uint8_t *)(p + 1), n.spi_size))
				goto trunc;
		}
		return (const u_char *)(p + 1) + n.spi_size;
	}

	ND_PRINT((ndo," doi=ipsec"));
	ND_PRINT((ndo," proto=%s", PROTOIDSTR(proto)));
	if (ntohs(n.type) < 8192)
		ND_PRINT((ndo," type=%s", NOTIFY_ERROR_STR(ntohs(n.type))));
	else if (ntohs(n.type) < 16384)
		ND_PRINT((ndo," type=%s", IPSEC_NOTIFY_ERROR_STR(ntohs(n.type))));
	else if (ntohs(n.type) < 24576)
		ND_PRINT((ndo," type=%s", NOTIFY_STATUS_STR(ntohs(n.type))));
	else if (ntohs(n.type) < 32768)
		ND_PRINT((ndo," type=%s", IPSEC_NOTIFY_STATUS_STR(ntohs(n.type))));
	else
		ND_PRINT((ndo," type=%s", numstr(ntohs(n.type))));
	if (n.spi_size) {
		ND_PRINT((ndo," spi="));
		if (!rawprint(ndo, (const uint8_t *)(p + 1), n.spi_size))
			goto trunc;
	}

	cp = (const u_char *)(p + 1) + n.spi_size;
	ep2 = (const u_char *)p + item_len;

	if (cp < ep) {
		switch (ntohs(n.type)) {
		case IPSECDOI_NTYPE_RESPONDER_LIFETIME:
		    {
			const struct attrmap *map = oakley_t_map;
 			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
 			ND_PRINT((ndo," attrs=("));
 			while (cp < ep && cp < ep2) {
				cp = ikev1_attrmap_print(ndo, cp,
					(ep < ep2) ? ep : ep2, map, nmap);
 			}
 			ND_PRINT((ndo,")"));
 			break;
		    }
		case IPSECDOI_NTYPE_REPLAY_STATUS:
			ND_PRINT((ndo," status=("));
			ND_PRINT((ndo,"replay detection %sabled",
				  EXTRACT_32BITS(cp) ? "en" : "dis"));
			ND_PRINT((ndo,")"));
			break;
		default:
			/*
			 * XXX - fill in more types here; see, for example,
			 * draft-ietf-ipsec-notifymsg-04.
			 */
			if (ndo->ndo_vflag > 3) {
				ND_PRINT((ndo," data=("));
				if (!rawprint(ndo, (const uint8_t *)(cp), ep - cp))
					goto trunc;
				ND_PRINT((ndo,")"));
			} else {
				if (!ike_show_somedata(ndo, cp, ep))
					goto trunc;
			}
			break;
		}
	}
	return (const u_char *)ext + item_len;
trunc:
	ND_PRINT((ndo," [|%s]", NPSTR(ISAKMP_NPTYPE_N)));
	return NULL;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **4**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-isakmp.c` **(funcao marcada esta aqui)** | modified | 58 | 25 |
| `tests/TESTLIST` | modified | 1 | 0 |
| `tests/isakmpv1-attr-oobr.out` | added | 3 | 0 |
| `tests/isakmpv1-attr-oobr.pcap` | added | 0 | 0 |


### `print-isakmp.c`

```diff
@@ -912,21 +912,25 @@ struct attrmap {
 
 static const u_char *
 ikev1_attrmap_print(netdissect_options *ndo,
-		    const u_char *p, const u_char *ep,
+		    const u_char *p, const u_char *ep2,
 		    const struct attrmap *map, size_t nmap)
 {
 	int totlen;
 	uint32_t t, v;
 
+	ND_TCHECK(p[0]);
 	if (p[0] & 0x80)
 		totlen = 4;
-	else
+	else {
+		ND_TCHECK_16BITS(&p[2]);
 		totlen = 4 + EXTRACT_16BITS(&p[2]);
-	if (ep < p + totlen) {
+	}
+	if (ep2 < p + totlen) {
 		ND_PRINT((ndo,"[|attr]"));
-		return ep + 1;
+		return ep2 + 1;
 	}
 
+	ND_TCHECK_16BITS(&p[0]);
 	ND_PRINT((ndo,"("));
 	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
 	if (map && t < nmap && map[t].type)
@@ -935,47 +939,71 @@ ikev1_attrmap_print(netdissect_options *ndo,
 		ND_PRINT((ndo,"type=#%d ", t));
 	if (p[0] & 0x80) {
 		ND_PRINT((ndo,"value="));
+		ND_TCHECK_16BITS(&p[2]);
 		v = EXTRACT_16BITS(&p[2]);
 		if (map && t < nmap && v < map[t].nvalue && map[t].value[v])
 			ND_PRINT((ndo,"%s", map[t].value[v]));
-		else
-			rawprint(ndo, (const uint8_t *)&p[2], 2);
+		else {
+			if (!rawprint(ndo, (const uint8_t *)&p[2], 2)) {
+				ND_PRINT((ndo,")"));
+				goto trunc;
+			}
+		}
 	} else {
-		ND_PRINT((ndo,"len=%d value=", EXTRACT_16BITS(&p[2])));
-		rawprint(ndo, (const uint8_t *)&p[4], EXTRACT_16BITS(&p[2]));
+		ND_PRINT((ndo,"len=%d value=", totlen - 4));
+		if (!rawprint(ndo, (const uint8_t *)&p[4], totlen - 4)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	}
 	ND_PRINT((ndo,")"));
 	return p + totlen;
+
+trunc:
+	return NULL;
 }
 
 static const u_char *
-ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep)
+ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep2)
 {
 	int totlen;
 	uint32_t t;
 
+	ND_TCHECK(p[0]);
 	if (p[0] & 0x80)
 		totlen = 4;
-	else
+	else {
+		ND_TCHECK_16BITS(&p[2]);
 		totlen = 4 + EXTRACT_16BITS(&p[2]);
-	if (ep < p + totlen) {
+	}
+	if (ep2 < p + totlen) {
 		ND_PRINT((ndo,"[|attr]"));
-		return ep + 1;
+		return ep2 + 1;
 	}
 
+	ND_TCHECK_16BITS(&p[0]);
 	ND_PRINT((ndo,"("));
 	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
 	ND_PRINT((ndo,"type=#%d ", t));
 	if (p[0] & 0x80) {
 		ND_PRINT((ndo,"value="));
 		t = p[2];
-		rawprint(ndo, (const uint8_t *)&p[2], 2);
+		if (!rawprint(ndo, (const uint8_t *)&p[2], 2)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	} else {
-		ND_PRINT((ndo,"len=%d value=", EXTRACT_16BITS(&p[2])));
-		rawprint(ndo, (const uint8_t *)&p[4], EXTRACT_16BITS(&p[2]));
+		ND_PRINT((ndo,"len=%d value=", totlen - 4));
+		if (!rawprint(ndo, (const uint8_t *)&p[4], totlen - 4)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	}
 	ND_PRINT((ndo,")"));
 	return p + totlen;
+
+trunc:
+	return NULL;
 }
 
 static const u_char *
@@ -1256,11 +1284,12 @@ ikev1_t_print(netdissect_options *ndo, u_char tpay _U_,
 	cp = (const u_char *)(p + 1);
 	ep2 = (const u_char *)p + item_len;
 	while (cp < ep && cp < ep2) {
-		if (map && nmap) {
-			cp = ikev1_attrmap_print(ndo, cp, (ep < ep2) ? ep : ep2,
-				map, nmap);
-		} else
-			cp = ikev1_attr_print(ndo, cp, (ep < ep2) ? ep : ep2);
+		if (map && nmap)
+			cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
+		else
+			cp = ikev1_attr_print(ndo, cp, ep2);
+		if (cp == NULL)
+			goto trunc;
 	}
 	if (ep < ep2)
 		ND_PRINT((ndo,"..."));
@@ -1724,8 +1753,11 @@ ikev1_n_print(netdissect_options *ndo, u_char tpay _U_,
 			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
 			ND_PRINT((ndo," attrs=("));
 			while (cp < ep && cp < ep2) {
-				cp = ikev1_attrmap_print(ndo, cp,
-					(ep < ep2) ? ep : ep2, map, nmap);
+				cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
+				if (cp == NULL) {
+					ND_PRINT((ndo,")"));
+					goto trunc;
+				}
 			}
 			ND_PRINT((ndo,")"));
 			break;
@@ -1926,10 +1958,11 @@ ikev2_t_print(netdissect_options *ndo, int tcount,
 	ep2 = (const u_char *)p + item_len;
 	while (cp < ep && cp < ep2) {
 		if (map && nmap) {
-			cp = ikev1_attrmap_print(ndo, cp, (ep < ep2) ? ep : ep2,
-				map, nmap);
+			cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
 		} else
-			cp = ikev1_attr_print(ndo, cp, (ep < ep2) ? ep : ep2);
+			cp = ikev1_attr_print(ndo, cp, ep2);
+		if (cp == NULL)
+			goto trunc;
 	}
 	if (ep < ep2)
 		ND_PRINT((ndo,"..."));
```


### `tests/TESTLIST`

```diff
@@ -553,6 +553,7 @@ ip6_frag_asan		ip6_frag_asan.pcap		ip6_frag_asan.out	-v
 radius_attr_asan	radius_attr_asan.pcap		radius_attr_asan.out	-v
 ospf6_decode_v3_asan	ospf6_decode_v3_asan.pcap	ospf6_decode_v3_asan.out -v
 ip_ts_opts_asan		ip_ts_opts_asan.pcap		ip_ts_opts_asan.out	-v
+isakmpv1-attr-oobr	isakmpv1-attr-oobr.pcap		isakmpv1-attr-oobr.out	-v
 
 # bad packets from Katie Holly
 mlppp-oobr		mlppp-oobr.pcap			mlppp-oobr.out
```


### `tests/isakmpv1-attr-oobr.out`

```diff
@@ -0,0 +1,3 @@
+IP (tos 0x60, ttl 254, id 40192, offset 0, flags [+, DF, rsvd], proto UDP (17), length 63264, options (unknown 255 [bad length 18]), bad cksum 8e30 (->f45)!)
+    251.73.77.150.32514 > 126.172.128.5.500: isakmp 1.0 msgid 2200af01: phase 2/others ? #40:
+    (t: #243 id=241 (type=#9472 len=2 value=0619) [|t]) (len mismatch: isakmp 4293885728/ip 2140)
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
