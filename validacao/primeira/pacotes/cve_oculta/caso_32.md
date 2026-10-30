# Pacote de anotacao — caso 32

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

# Evidencia do caso 32

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-125
- arquivo da funcao marcada: `print-decnet.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -43,6 +43,7 @@
  	    length -= padlen;
  	    caplen -= padlen;
  	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
+	    ND_TCHECK(rhp->rh_short.sh_flags);
  	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
  	}
  
```

## Corpo completo da funcao antes da correcao

```c
decnet_print(netdissect_options *ndo,
             register const u_char *ap, register u_int length,
             register u_int caplen)
{
	register const union routehdr *rhp;
	register int mflags;
	int dst, src, hops;
	u_int nsplen, pktlen;
	const u_char *nspp;

	if (length < sizeof(struct shorthdr)) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}

	ND_TCHECK2(*ap, sizeof(short));
	pktlen = EXTRACT_LE_16BITS(ap);
	if (pktlen < sizeof(struct shorthdr)) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}
	if (pktlen > length) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}
	length = pktlen;

	rhp = (const union routehdr *)&(ap[sizeof(short)]);
	ND_TCHECK(rhp->rh_short.sh_flags);
	mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);

	if (mflags & RMF_PAD) {
	    /* pad bytes of some sort in front of message */
	    u_int padlen = mflags & RMF_PADMASK;
	    if (ndo->ndo_vflag)
		ND_PRINT((ndo, "[pad:%d] ", padlen));
	    if (length < padlen + 2) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	    }
	    ND_TCHECK2(ap[sizeof(short)], padlen);
	    ap += padlen;
 	    length -= padlen;
 	    caplen -= padlen;
 	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
 	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
 	}
 
	if (mflags & RMF_FVER) {
		ND_PRINT((ndo, "future-version-decnet"));
		ND_DEFAULTPRINT(ap, min(length, caplen));
		return;
	}

	/* is it a control message? */
	if (mflags & RMF_CTLMSG) {
		if (!print_decnet_ctlmsg(ndo, rhp, length, caplen))
			goto trunc;
		return;
	}

	switch (mflags & RMF_MASK) {
	case RMF_LONG:
	    if (length < sizeof(struct longhdr)) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	    }
	    ND_TCHECK(rhp->rh_long);
	    dst =
		EXTRACT_LE_16BITS(rhp->rh_long.lg_dst.dne_remote.dne_nodeaddr);
	    src =
		EXTRACT_LE_16BITS(rhp->rh_long.lg_src.dne_remote.dne_nodeaddr);
	    hops = EXTRACT_LE_8BITS(rhp->rh_long.lg_visits);
	    nspp = &(ap[sizeof(short) + sizeof(struct longhdr)]);
	    nsplen = length - sizeof(struct longhdr);
	    break;
	case RMF_SHORT:
	    ND_TCHECK(rhp->rh_short);
	    dst = EXTRACT_LE_16BITS(rhp->rh_short.sh_dst);
	    src = EXTRACT_LE_16BITS(rhp->rh_short.sh_src);
	    hops = (EXTRACT_LE_8BITS(rhp->rh_short.sh_visits) & VIS_MASK)+1;
	    nspp = &(ap[sizeof(short) + sizeof(struct shorthdr)]);
	    nsplen = length - sizeof(struct shorthdr);
	    break;
	default:
	    ND_PRINT((ndo, "unknown message flags under mask"));
	    ND_DEFAULTPRINT((const u_char *)ap, min(length, caplen));
	    return;
	}

	ND_PRINT((ndo, "%s > %s %d ",
			dnaddr_string(ndo, src), dnaddr_string(ndo, dst), pktlen));
	if (ndo->ndo_vflag) {
	    if (mflags & RMF_RQR)
		ND_PRINT((ndo, "RQR "));
	    if (mflags & RMF_RTS)
		ND_PRINT((ndo, "RTS "));
	    if (mflags & RMF_IE)
		ND_PRINT((ndo, "IE "));
	    ND_PRINT((ndo, "%d hops ", hops));
	}

	if (!print_nsp(ndo, nspp, nsplen))
		goto trunc;
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
	return;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **4**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-decnet.c` **(funcao marcada esta aqui)** | modified | 2 | 0 |
| `tests/TESTLIST` | modified | 1 | 0 |
| `tests/decnet-oobr.out` | added | 4 | 0 |
| `tests/decnet-oobr.pcap` | added | 0 | 0 |


### `print-decnet.c`

```diff
@@ -542,6 +542,7 @@ decnet_print(netdissect_options *ndo,
 	    length -= padlen;
 	    caplen -= padlen;
 	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
+	    ND_TCHECK(rhp->rh_short.sh_flags);
 	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
 	}
 
@@ -613,6 +614,7 @@ print_decnet_ctlmsg(netdissect_options *ndo,
                     register const union routehdr *rhp, u_int length,
                     u_int caplen)
 {
+	/* Our caller has already checked for mflags */
 	int mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
 	register const union controlmsg *cmp = (const union controlmsg *)rhp;
 	int src, dst, info, blksize, eco, ueco, hello, other, vers;
```


### `tests/TESTLIST`

```diff
@@ -444,6 +444,7 @@ hoobr_safeputs		hoobr_safeputs.pcap		hoobr_safeputs.out
 isakmp-rfc3948-oobr	isakmp-rfc3948-oobr.pcap	isakmp-rfc3948-oobr.out
 isoclns-oobr		isoclns-oobr.pcap		isoclns-oobr.out
 nfs-attr-oobr		nfs-attr-oobr.pcap		nfs-attr-oobr.out
+decnet-oobr		decnet-oobr.pcap		decnet-oobr.out
 
 # bad packets from Wilfried Kirsch
 slip-bad-direction	slip-bad-direction.pcap		slip-bad-direction.out	-ve
```


### `tests/decnet-oobr.out`

```diff
@@ -0,0 +1,4 @@
+30:30:30:30:30:30 > 30:30:30:30:30:30, ethertype Unknown (0x3030), length 808464432: 
+	0x0000:  3030 3030 3030 3030 3030 3030 3030 3030  0000000000000000
+	0x0010:  3030 3030                                0000
+MEDSA 16.6:48: [|decnet]
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
