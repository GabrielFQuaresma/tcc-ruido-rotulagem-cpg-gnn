# Pacote de anotacao — caso 03

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

# Evidencia do caso 03

## Identificacao

- projeto: tcpdump
- CVE: CVE-2017-12985
- CWE atribuida pelo BigVul: CWE-125
- commit: `66df248b49095c261138b5a5e34d341a6bf9ac7f`
- URL do commit: https://github.com/the-tcpdump-group/tcpdump/commit/66df248b49095c261138b5a5e34d341a6bf9ac7f
- arquivo da funcao marcada: `print-ip6.c`

## Mensagem do commit

> CVE-2017-12985/IPv6: Check for print routines returning -1 when running past the end.
> 
> rt6_print(), ah_print(), and esp_print() return -1 if they run up
> against the end of the packet while dissecting; if that happens, stop
> dissecting, don't try to fetch the next header value, because 1) *it*
> might be past the end of the packet and 2) we won't be using it in any
> case, as we'll be exiting the loop.
> 
> Also, change mobility_print() to return -1 if it runs up against the
> end of the packet, and stop dissecting if it does so.
> 
> This fixes a buffer over-read discovered by Brian 'geeknik' Carpenter.
> 
> Add tests using the capture files supplied by the reporter(s).

## Resumo da CVE

> The IPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-ip6.c:ip6_print().

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -67,6 +67,8 @@
  	advance = sizeof(struct ip6_hdr);
  	nh = ip6->ip6_nxt;
  	while (cp < ndo->ndo_snapend && advance > 0) {
+		if (len < (u_int)advance)
+			goto trunc;
  		cp += advance;
  		len -= advance;
  
@@ -109,10 +111,15 @@
  			 * mobility header.
  			 */
  			advance = mobility_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
  			nh = *cp;
  			return;
  		case IPPROTO_ROUTING:
+			ND_TCHECK(*cp);
  			advance = rt6_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
  			nh = *cp;
  			break;
  		case IPPROTO_SCTP:
@@ -132,12 +139,16 @@
  			return;
  		case IPPROTO_AH:
  			advance = ah_print(ndo, cp);
+			if (advance < 0)
+				return;
  			nh = *cp;
  			break;
  		case IPPROTO_ESP:
  		    {
  			int enh, padlen;
  			advance = esp_print(ndo, cp, len, (const u_char *)ip6, &enh, &padlen);
+			if (advance < 0)
+				return;
  			nh = enh & 0xff;
  			len -= padlen;
  			break;
```

## Corpo completo da funcao antes da correcao

```c
ip6_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	register const struct ip6_hdr *ip6;
	register int advance;
	u_int len;
	const u_char *ipend;
	register const u_char *cp;
	register u_int payload_len;
	int nh;
	int fragmented = 0;
	u_int flow;

	ip6 = (const struct ip6_hdr *)bp;

	ND_TCHECK(*ip6);
	if (length < sizeof (struct ip6_hdr)) {
		ND_PRINT((ndo, "truncated-ip6 %u", length));
		return;
	}

        if (!ndo->ndo_eflag)
            ND_PRINT((ndo, "IP6 "));

	if (IP6_VERSION(ip6) != 6) {
          ND_PRINT((ndo,"version error: %u != 6", IP6_VERSION(ip6)));
          return;
	}

	payload_len = EXTRACT_16BITS(&ip6->ip6_plen);
	len = payload_len + sizeof(struct ip6_hdr);
	if (length < len)
		ND_PRINT((ndo, "truncated-ip6 - %u bytes missing!",
			len - length));

        if (ndo->ndo_vflag) {
            flow = EXTRACT_32BITS(&ip6->ip6_flow);
            ND_PRINT((ndo, "("));
#if 0
            /* rfc1883 */
            if (flow & 0x0f000000)
		ND_PRINT((ndo, "pri 0x%02x, ", (flow & 0x0f000000) >> 24));
            if (flow & 0x00ffffff)
		ND_PRINT((ndo, "flowlabel 0x%06x, ", flow & 0x00ffffff));
#else
            /* RFC 2460 */
            if (flow & 0x0ff00000)
		ND_PRINT((ndo, "class 0x%02x, ", (flow & 0x0ff00000) >> 20));
            if (flow & 0x000fffff)
		ND_PRINT((ndo, "flowlabel 0x%05x, ", flow & 0x000fffff));
#endif

            ND_PRINT((ndo, "hlim %u, next-header %s (%u) payload length: %u) ",
                         ip6->ip6_hlim,
                         tok2str(ipproto_values,"unknown",ip6->ip6_nxt),
                         ip6->ip6_nxt,
                         payload_len));
        }

	/*
	 * Cut off the snapshot length to the end of the IP payload.
	 */
	ipend = bp + len;
	if (ipend < ndo->ndo_snapend)
		ndo->ndo_snapend = ipend;

	cp = (const u_char *)ip6;
 	advance = sizeof(struct ip6_hdr);
 	nh = ip6->ip6_nxt;
 	while (cp < ndo->ndo_snapend && advance > 0) {
 		cp += advance;
 		len -= advance;
 
		if (cp == (const u_char *)(ip6 + 1) &&
		    nh != IPPROTO_TCP && nh != IPPROTO_UDP &&
		    nh != IPPROTO_DCCP && nh != IPPROTO_SCTP) {
			ND_PRINT((ndo, "%s > %s: ", ip6addr_string(ndo, &ip6->ip6_src),
				     ip6addr_string(ndo, &ip6->ip6_dst)));
		}

		switch (nh) {
		case IPPROTO_HOPOPTS:
			advance = hbhopt_print(ndo, cp);
			if (advance < 0)
				return;
			nh = *cp;
			break;
		case IPPROTO_DSTOPTS:
			advance = dstopt_print(ndo, cp);
			if (advance < 0)
				return;
			nh = *cp;
			break;
		case IPPROTO_FRAGMENT:
			advance = frag6_print(ndo, cp, (const u_char *)ip6);
			if (advance < 0 || ndo->ndo_snapend <= cp + advance)
				return;
			nh = *cp;
			fragmented = 1;
			break;

		case IPPROTO_MOBILITY_OLD:
		case IPPROTO_MOBILITY:
			/*
			 * XXX - we don't use "advance"; RFC 3775 says that
			 * the next header field in a mobility header
			 * should be IPPROTO_NONE, but speaks of
			 * the possiblity of a future extension in
			 * which payload can be piggybacked atop a
 			 * mobility header.
 			 */
 			advance = mobility_print(ndo, cp, (const u_char *)ip6);
 			nh = *cp;
 			return;
 		case IPPROTO_ROUTING:
 			advance = rt6_print(ndo, cp, (const u_char *)ip6);
 			nh = *cp;
 			break;
 		case IPPROTO_SCTP:
			sctp_print(ndo, cp, (const u_char *)ip6, len);
			return;
		case IPPROTO_DCCP:
			dccp_print(ndo, cp, (const u_char *)ip6, len);
			return;
		case IPPROTO_TCP:
			tcp_print(ndo, cp, len, (const u_char *)ip6, fragmented);
			return;
		case IPPROTO_UDP:
			udp_print(ndo, cp, len, (const u_char *)ip6, fragmented);
			return;
		case IPPROTO_ICMPV6:
			icmp6_print(ndo, cp, len, (const u_char *)ip6, fragmented);
 			return;
 		case IPPROTO_AH:
 			advance = ah_print(ndo, cp);
 			nh = *cp;
 			break;
 		case IPPROTO_ESP:
 		    {
 			int enh, padlen;
 			advance = esp_print(ndo, cp, len, (const u_char *)ip6, &enh, &padlen);
 			nh = enh & 0xff;
 			len -= padlen;
 			break;
		    }
		case IPPROTO_IPCOMP:
		    {
			ipcomp_print(ndo, cp);
			/*
			 * Either this has decompressed the payload and
			 * printed it, in which case there's nothing more
			 * to do, or it hasn't, in which case there's
			 * nothing more to do.
			 */
			advance = -1;
			break;
		    }

		case IPPROTO_PIM:
			pim_print(ndo, cp, len, (const u_char *)ip6);
			return;

		case IPPROTO_OSPF:
			ospf6_print(ndo, cp, len);
			return;

		case IPPROTO_IPV6:
			ip6_print(ndo, cp, len);
			return;

		case IPPROTO_IPV4:
		        ip_print(ndo, cp, len);
			return;

                case IPPROTO_PGM:
                        pgm_print(ndo, cp, len, (const u_char *)ip6);
                        return;

		case IPPROTO_GRE:
			gre_print(ndo, cp, len);
			return;

		case IPPROTO_RSVP:
			rsvp_print(ndo, cp, len);
			return;

		case IPPROTO_NONE:
			ND_PRINT((ndo, "no next header"));
			return;

		default:
			ND_PRINT((ndo, "ip-proto-%d %d", nh, len));
			return;
		}
	}

	return;
trunc:
	ND_PRINT((ndo, "[|ip6]"));
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **7**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-ip6.c` **(funcao marcada esta aqui)** | modified | 11 | 0 |
| `print-mobility.c` | modified | 1 | 1 |
| `tests/TESTLIST` | modified | 2 | 0 |
| `tests/ipv6-next-header-oobr-1.out` | added | 1 | 0 |
| `tests/ipv6-next-header-oobr-1.pcap` | added | 0 | 0 |
| `tests/ipv6-next-header-oobr-2.out` | added | 1 | 0 |
| `tests/ipv6-next-header-oobr-2.pcap` | added | 0 | 0 |


### `print-ip6.c`

```diff
@@ -280,6 +280,8 @@ ip6_print(netdissect_options *ndo, const u_char *bp, u_int length)
 	advance = sizeof(struct ip6_hdr);
 	nh = ip6->ip6_nxt;
 	while (cp < ndo->ndo_snapend && advance > 0) {
+		if (len < (u_int)advance)
+			goto trunc;
 		cp += advance;
 		len -= advance;
 
@@ -322,10 +324,15 @@ ip6_print(netdissect_options *ndo, const u_char *bp, u_int length)
 			 * mobility header.
 			 */
 			advance = mobility_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			return;
 		case IPPROTO_ROUTING:
+			ND_TCHECK(*cp);
 			advance = rt6_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			break;
 		case IPPROTO_SCTP:
@@ -345,12 +352,16 @@ ip6_print(netdissect_options *ndo, const u_char *bp, u_int length)
 			return;
 		case IPPROTO_AH:
 			advance = ah_print(ndo, cp);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			break;
 		case IPPROTO_ESP:
 		    {
 			int enh, padlen;
 			advance = esp_print(ndo, cp, len, (const u_char *)ip6, &enh, &padlen);
+			if (advance < 0)
+				return;
 			nh = enh & 0xff;
 			len -= padlen;
 			break;
```


### `print-mobility.c`

```diff
@@ -332,5 +332,5 @@ mobility_print(netdissect_options *ndo,
 
  trunc:
 	ND_PRINT((ndo, "%s", tstr));
-	return(mhlen);
+	return(-1);
 }
```


### `tests/TESTLIST`

```diff
@@ -432,6 +432,8 @@ otv-heapoverflow-1	otv-heapoverflow-1.pcap		otv-heapoverflow-1.out		-c10
 otv-heapoverflow-2	otv-heapoverflow-2.pcap		otv-heapoverflow-2.out		-c10
 q933-heapoverflow-2	q933-heapoverflow-2.pcap	q933-heapoverflow-2.out
 atm-heapoverflow	atm-heapoverflow.pcap		atm-heapoverflow.out		-c1 -e
+ipv6-next-header-oobr-1	ipv6-next-header-oobr-1.pcap	ipv6-next-header-oobr-1.out
+ipv6-next-header-oobr-2	ipv6-next-header-oobr-2.pcap	ipv6-next-header-oobr-2.out
 
 # bad packets from Kamil Frankowicz
 snmp-heapoverflow-1	snmp-heapoverflow-1.pcap	snmp-heapoverflow-1.out
```


### `tests/ipv6-next-header-oobr-1.out`

```diff
@@ -0,0 +1 @@
+IP6 3030:3030:3030:3030:3030:3030:3030:3030 > 3030:3030:3030:3030:3030:3030:3030:3030: HBH [|ip6]
```


### `tests/ipv6-next-header-oobr-2.out`

```diff
@@ -0,0 +1 @@
+IP6 3030:3030:3030:3030:3030:3030:3030:3030 > 3030:3030:3030:3030:3030:3030:3030:3030: HBH [|AH]
```


_[2 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
