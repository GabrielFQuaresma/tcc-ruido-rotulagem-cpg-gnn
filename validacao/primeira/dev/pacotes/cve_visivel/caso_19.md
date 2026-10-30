# Pacote de anotacao — caso 19

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

# Evidencia do caso 19

## Identificacao

- projeto: tcpdump
- CVE: CVE-2017-13053
- CWE atribuida pelo BigVul: CWE-125
- commit: `bd4e697ebd6c8457efa8f28f6831fc929b88a014`
- URL do commit: https://github.com/the-tcpdump-group/tcpdump/commit/bd4e697ebd6c8457efa8f28f6831fc929b88a014
- arquivo da funcao marcada: `print-bgp.c`

## Mensagem do commit

> CVE-2017-13053/BGP: fix VPN route target bounds checks
> 
> decode_rt_routing_info() didn't check bounds before fetching 4 octets of
> the origin AS field and could over-read the input buffer, put it right.
> 
> It also fetched the varying number of octets of the route target field
> from 4 octets lower than the correct offset, put it right.
> 
> It also used the same temporary buffer explicitly through as_printf()
> and implicitly through bgp_vpn_rd_print() so the end result of snprintf()
> was not what was originally intended.
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s).

## Resumo da CVE

> The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:decode_rt_routing_info().

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -3,11 +3,18 @@
  {
  	uint8_t route_target[8];
  	u_int plen;
+	char asbuf[sizeof(astostr)]; /* bgp_vpn_rd_print() overwrites astostr */
  
+	/* NLRI "prefix length" from RFC 2858 Section 4. */
  	ND_TCHECK(pptr[0]);
  	plen = pptr[0];   /* get prefix length */
  
+	/* NLRI "prefix" (ibid), valid lengths are { 0, 32, 33, ..., 96 } bits.
+	 * RFC 4684 Section 4 defines the layout of "origin AS" and "route
+	 * target" fields inside the "prefix" depending on its length.
+	 */
  	if (0 == plen) {
+		/* Without "origin AS", without "route target". */
  		snprintf(buf, buflen, "default route target");
  		return 1;
  	}
@@ -15,20 +22,29 @@
  	if (32 > plen)
  		return -1;
  
+	/* With at least "origin AS", possibly with "route target". */
+	ND_TCHECK_32BITS(pptr + 1);
+	as_printf(ndo, asbuf, sizeof(asbuf), EXTRACT_32BITS(pptr + 1));
+
          plen-=32; /* adjust prefix length */
  
  	if (64 < plen)
  		return -1;
  
+	/* From now on (plen + 7) / 8 evaluates to { 0, 1, 2, ..., 8 }
+	 * and gives the number of octets in the variable-length "route
+	 * target" field inside this NLRI "prefix". Look for it.
+	 */
  	memset(&route_target, 0, sizeof(route_target));
-	ND_TCHECK2(pptr[1], (plen + 7) / 8);
-	memcpy(&route_target, &pptr[1], (plen + 7) / 8);
+	ND_TCHECK2(pptr[5], (plen + 7) / 8);
+	memcpy(&route_target, &pptr[5], (plen + 7) / 8);
+	/* Which specification says to do this? */
  	if (plen % 8) {
  		((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
  			((0xff00 >> (plen % 8)) & 0xff);
  	}
  	snprintf(buf, buflen, "origin AS: %s, route target %s",
-	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+1)),
+	    asbuf,
  	    bgp_vpn_rd_print(ndo, (u_char *)&route_target));
  
  	return 5 + (plen + 7) / 8;
```

## Corpo completo da funcao antes da correcao

```c
decode_rt_routing_info(netdissect_options *ndo,
                       const u_char *pptr, char *buf, u_int buflen)
 {
 	uint8_t route_target[8];
 	u_int plen;
 
 	ND_TCHECK(pptr[0]);
 	plen = pptr[0];   /* get prefix length */
 
 	if (0 == plen) {
 		snprintf(buf, buflen, "default route target");
 		return 1;
 	}
 
 	if (32 > plen)
 		return -1;
 
         plen-=32; /* adjust prefix length */
 
 	if (64 < plen)
 		return -1;
 
 	memset(&route_target, 0, sizeof(route_target));
	ND_TCHECK2(pptr[1], (plen + 7) / 8);
	memcpy(&route_target, &pptr[1], (plen + 7) / 8);
 	if (plen % 8) {
 		((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
 			((0xff00 >> (plen % 8)) & 0xff);
 	}
 	snprintf(buf, buflen, "origin AS: %s, route target %s",
	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+1)),
 	    bgp_vpn_rd_print(ndo, (u_char *)&route_target));
 
 	return 5 + (plen + 7) / 8;

trunc:
	return -2;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **4**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-bgp.c` **(funcao marcada esta aqui)** | modified | 19 | 3 |
| `tests/TESTLIST` | modified | 1 | 0 |
| `tests/bgp_vpn_rt-oobr.out` | added | 43 | 0 |
| `tests/bgp_vpn_rt-oobr.pcap` | added | 0 | 0 |


### `print-bgp.c`

```diff
@@ -761,32 +761,48 @@ decode_rt_routing_info(netdissect_options *ndo,
 {
 	uint8_t route_target[8];
 	u_int plen;
+	char asbuf[sizeof(astostr)]; /* bgp_vpn_rd_print() overwrites astostr */
 
+	/* NLRI "prefix length" from RFC 2858 Section 4. */
 	ND_TCHECK(pptr[0]);
 	plen = pptr[0];   /* get prefix length */
 
+	/* NLRI "prefix" (ibid), valid lengths are { 0, 32, 33, ..., 96 } bits.
+	 * RFC 4684 Section 4 defines the layout of "origin AS" and "route
+	 * target" fields inside the "prefix" depending on its length.
+	 */
 	if (0 == plen) {
+		/* Without "origin AS", without "route target". */
 		snprintf(buf, buflen, "default route target");
 		return 1;
 	}
 
 	if (32 > plen)
 		return -1;
 
+	/* With at least "origin AS", possibly with "route target". */
+	ND_TCHECK_32BITS(pptr + 1);
+	as_printf(ndo, asbuf, sizeof(asbuf), EXTRACT_32BITS(pptr + 1));
+
         plen-=32; /* adjust prefix length */
 
 	if (64 < plen)
 		return -1;
 
+	/* From now on (plen + 7) / 8 evaluates to { 0, 1, 2, ..., 8 }
+	 * and gives the number of octets in the variable-length "route
+	 * target" field inside this NLRI "prefix". Look for it.
+	 */
 	memset(&route_target, 0, sizeof(route_target));
-	ND_TCHECK2(pptr[1], (plen + 7) / 8);
-	memcpy(&route_target, &pptr[1], (plen + 7) / 8);
+	ND_TCHECK2(pptr[5], (plen + 7) / 8);
+	memcpy(&route_target, &pptr[5], (plen + 7) / 8);
+	/* Which specification says to do this? */
 	if (plen % 8) {
 		((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
 			((0xff00 >> (plen % 8)) & 0xff);
 	}
 	snprintf(buf, buflen, "origin AS: %s, route target %s",
-	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+1)),
+	    asbuf,
 	    bgp_vpn_rd_print(ndo, (u_char *)&route_target));
 
 	return 5 + (plen + 7) / 8;
```


### `tests/TESTLIST`

```diff
@@ -572,6 +572,7 @@ rsvp_uni-oobr-2	rsvp_uni-oobr-2.pcap	rsvp_uni-oobr-2.out	-v -c1
 rsvp_uni-oobr-3	rsvp_uni-oobr-3.pcap	rsvp_uni-oobr-3.out	-v -c3
 rpki-rtr-oob		rpki-rtr-oob.pcap	rpki-rtr-oob.out	-v -c1
 lldp_8023_mtu-oobr	lldp_8023_mtu-oobr.pcap	lldp_8023_mtu-oobr.out	-v -c1
+bgp_vpn_rt-oobr	bgp_vpn_rt-oobr.pcap	bgp_vpn_rt-oobr.out	-v -c1
 
 # bad packets from Katie Holly
 mlppp-oobr		mlppp-oobr.pcap			mlppp-oobr.out
```


### `tests/bgp_vpn_rt-oobr.out`

```diff
@@ -0,0 +1,43 @@
+IP (tos 0xc, ttl 254, id 21263, offset 0, flags [rsvd], proto TCP (6), length 60165, bad cksum 8e15 (->9eb8)!)
+    241.0.128.19.179 > 239.8.0.1.0: Flags [none], seq 2146695561:2146755682, win 56026, options [unknown-161,eol], length 60121: BGP
+	Update Message (2), length: 45
+	  Withdrawn routes: 3 bytes
+	  Attribute Set (128), length: 7, Flags [OTPE+f]: 
+	    Origin AS: 0
+	      Multi-Protocol Unreach NLRI (15), length: 227, Flags [T+6]: 
+	    AFI: IPv6 (2), SAFI: Multicast VPN (5)
+	      Route-Type: Source-Active (5), length: 5, RD: unknown RD format, Group bogus address length 127
+	      Route-Type: Unknown (142), length: 142
+	      Route-Type: Unknown (0), length: 0
+	      Route-Type: Unknown (33), length: 0
+	      Route-Type: Unknown (0), length: 0[|BGP] [|BGP]
+	Update Message (2), length: 45[|BGP] [|BGP]
+	Update Message (2), length: 45
+	  Withdrawn routes: 3 bytes
+	  Attribute Set (128), length: 7, Flags [OTPE+f]: 
+	    Origin AS: 0
+	      Multi-Protocol Reach NLRI (14), length: 227, Flags [T+6]: 
+	    AFI: IPv4 (1), vendor specific SAFI: Route Target Routing Information (132)
+	    nexthop: invalid len, nh-length: 1, no SNPA
+	      origin AS: 0, route target 0:0 (= 0.0.0.0)
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target
+	      default route target[|BGP]
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
