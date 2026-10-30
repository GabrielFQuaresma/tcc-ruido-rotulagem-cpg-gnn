# Pacote de anotacao — caso 09

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

# Evidencia do caso 09

## Identificacao

- projeto: tcpdump
- CVE: CVE-2018-14464
- CWE atribuida pelo BigVul: CWE-125
- commit: `d97e94223720684c6aa740ff219e0d19426c2220`
- URL do commit: https://github.com/the-tcpdump-group/tcpdump/commit/d97e94223720684c6aa740ff219e0d19426c2220
- arquivo da funcao marcada: `print-lmp.c`

## Mensagem do commit

> (for 4.9.3) CVE-2018-14464/LMP: Add a missing bounds check
> 
> In lmp_print_data_link_subobjs().
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s).

## Resumo da CVE

> The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-lmp.c:lmp_print_data_link_subobjs().

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -5,7 +5,7 @@
      const struct lmp_object_header *lmp_obj_header;
      const u_char *tptr,*obj_tptr;
      u_int tlen,lmp_obj_len,lmp_obj_ctype,obj_tlen;
-    int hexdump;
+    int hexdump, ret;
      u_int offset;
      u_int link_type;
  
@@ -307,7 +307,10 @@
                         ipaddr_string(ndo, obj_tptr+8),
                         EXTRACT_32BITS(obj_tptr+8)));
  
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
  		    hexdump=TRUE;
  		break;
  
@@ -327,7 +330,10 @@
                         ip6addr_string(ndo, obj_tptr+20),
                         EXTRACT_32BITS(obj_tptr+20)));
  
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
  		    hexdump=TRUE;
  		break;
  
@@ -347,7 +353,10 @@
                         EXTRACT_32BITS(obj_tptr+8),
                         EXTRACT_32BITS(obj_tptr+8)));
  
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
  		    hexdump=TRUE;
  		break;
  
```

## Corpo completo da funcao antes da correcao

```c
lmp_print(netdissect_options *ndo,
          register const u_char *pptr, register u_int len)
{
    const struct lmp_common_header *lmp_com_header;
     const struct lmp_object_header *lmp_obj_header;
     const u_char *tptr,*obj_tptr;
     u_int tlen,lmp_obj_len,lmp_obj_ctype,obj_tlen;
    int hexdump;
     u_int offset;
     u_int link_type;
 
    union { /* int to float conversion buffer */
        float f;
        uint32_t i;
    } bw;

    tptr=pptr;
    lmp_com_header = (const struct lmp_common_header *)pptr;
    ND_TCHECK(*lmp_com_header);

    /*
     * Sanity checking of the header.
     */
    if (LMP_EXTRACT_VERSION(lmp_com_header->version_res[0]) != LMP_VERSION) {
	ND_PRINT((ndo, "LMP version %u packet not supported",
               LMP_EXTRACT_VERSION(lmp_com_header->version_res[0])));
	return;
    }

    /* in non-verbose mode just lets print the basic Message Type*/
    if (ndo->ndo_vflag < 1) {
        ND_PRINT((ndo, "LMPv%u %s Message, length: %u",
               LMP_EXTRACT_VERSION(lmp_com_header->version_res[0]),
               tok2str(lmp_msg_type_values, "unknown (%u)",lmp_com_header->msg_type),
               len));
        return;
    }

    /* ok they seem to want to know everything - lets fully decode it */

    tlen=EXTRACT_16BITS(lmp_com_header->length);

    ND_PRINT((ndo, "\n\tLMPv%u, msg-type: %s, Flags: [%s], length: %u",
           LMP_EXTRACT_VERSION(lmp_com_header->version_res[0]),
           tok2str(lmp_msg_type_values, "unknown, type: %u",lmp_com_header->msg_type),
           bittok2str(lmp_header_flag_values,"none",lmp_com_header->flags),
           tlen));
    if (tlen < sizeof(const struct lmp_common_header)) {
        ND_PRINT((ndo, " (too short)"));
        return;
    }
    if (tlen > len) {
        ND_PRINT((ndo, " (too long)"));
        tlen = len;
    }

    tptr+=sizeof(const struct lmp_common_header);
    tlen-=sizeof(const struct lmp_common_header);

    while(tlen>0) {
        /* did we capture enough for fully decoding the object header ? */
        ND_TCHECK2(*tptr, sizeof(struct lmp_object_header));

        lmp_obj_header = (const struct lmp_object_header *)tptr;
        lmp_obj_len=EXTRACT_16BITS(lmp_obj_header->length);
        lmp_obj_ctype=(lmp_obj_header->ctype)&0x7f;

        ND_PRINT((ndo, "\n\t  %s Object (%u), Class-Type: %s (%u) Flags: [%snegotiable], length: %u",
               tok2str(lmp_obj_values,
                       "Unknown",
                       lmp_obj_header->class_num),
               lmp_obj_header->class_num,
               tok2str(lmp_ctype_values,
                       "Unknown",
                       ((lmp_obj_header->class_num)<<8)+lmp_obj_ctype),
               lmp_obj_ctype,
               (lmp_obj_header->ctype)&0x80 ? "" : "non-",
               lmp_obj_len));

        if (lmp_obj_len < 4) {
            ND_PRINT((ndo, " (too short)"));
            return;
        }
        if ((lmp_obj_len % 4) != 0) {
            ND_PRINT((ndo, " (not a multiple of 4)"));
            return;
        }

        obj_tptr=tptr+sizeof(struct lmp_object_header);
        obj_tlen=lmp_obj_len-sizeof(struct lmp_object_header);

        /* did we capture enough for fully decoding the object ? */
        ND_TCHECK2(*tptr, lmp_obj_len);
        hexdump=FALSE;

        switch(lmp_obj_header->class_num) {

        case LMP_OBJ_CC_ID:
            switch(lmp_obj_ctype) {
            case LMP_CTYPE_LOC:
            case LMP_CTYPE_RMT:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Control Channel ID: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_LINK_ID:
        case LMP_OBJ_INTERFACE_ID:
            switch(lmp_obj_ctype) {
            case LMP_CTYPE_IPV4_LOC:
            case LMP_CTYPE_IPV4_RMT:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    IPv4 Link ID: %s (0x%08x)",
                       ipaddr_string(ndo, obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;
            case LMP_CTYPE_IPV6_LOC:
            case LMP_CTYPE_IPV6_RMT:
                if (obj_tlen != 16) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    IPv6 Link ID: %s (0x%08x)",
                       ip6addr_string(ndo, obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;
            case LMP_CTYPE_UNMD_LOC:
            case LMP_CTYPE_UNMD_RMT:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Link ID: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;
            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_MESSAGE_ID:
            switch(lmp_obj_ctype) {
            case LMP_CTYPE_1:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Message ID: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;
            case LMP_CTYPE_2:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Message ID Ack: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;
            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_NODE_ID:
            switch(lmp_obj_ctype) {
            case LMP_CTYPE_LOC:
            case LMP_CTYPE_RMT:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Node ID: %s (0x%08x)",
                       ipaddr_string(ndo, obj_tptr),
                       EXTRACT_32BITS(obj_tptr)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_CONFIG:
            switch(lmp_obj_ctype) {
            case LMP_CTYPE_HELLO_CONFIG:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Hello Interval: %u\n\t    Hello Dead Interval: %u",
                       EXTRACT_16BITS(obj_tptr),
                       EXTRACT_16BITS(obj_tptr+2)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_HELLO:
            switch(lmp_obj_ctype) {
	    case LMP_CTYPE_HELLO:
                if (obj_tlen != 8) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Tx Seq: %u, Rx Seq: %u",
                       EXTRACT_32BITS(obj_tptr),
                       EXTRACT_32BITS(obj_tptr+4)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_TE_LINK:
	    switch(lmp_obj_ctype) {
	    case LMP_CTYPE_IPV4:
                if (obj_tlen != 12) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_te_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));

		ND_PRINT((ndo, "\n\t    Local Link-ID: %s (0x%08x)"
		       "\n\t    Remote Link-ID: %s (0x%08x)",
                       ipaddr_string(ndo, obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                       ipaddr_string(ndo, obj_tptr+8),
                       EXTRACT_32BITS(obj_tptr+8)));
		break;

	    case LMP_CTYPE_IPV6:
                if (obj_tlen != 36) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_te_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));

		ND_PRINT((ndo, "\n\t    Local Link-ID: %s (0x%08x)"
		       "\n\t    Remote Link-ID: %s (0x%08x)",
                       ip6addr_string(ndo, obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                       ip6addr_string(ndo, obj_tptr+20),
                       EXTRACT_32BITS(obj_tptr+20)));
                break;

	    case LMP_CTYPE_UNMD:
                if (obj_tlen != 12) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_te_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));

		ND_PRINT((ndo, "\n\t    Local Link-ID: %u (0x%08x)"
		       "\n\t    Remote Link-ID: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+8),
                       EXTRACT_32BITS(obj_tptr+8)));
		break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_DATA_LINK:
	    switch(lmp_obj_ctype) {
	    case LMP_CTYPE_IPV4:
                if (obj_tlen < 12) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
	        ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_data_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));
                ND_PRINT((ndo, "\n\t    Local Interface ID: %s (0x%08x)"
                       "\n\t    Remote Interface ID: %s (0x%08x)",
                       ipaddr_string(ndo, obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                        ipaddr_string(ndo, obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
 		    hexdump=TRUE;
 		break;
 
	    case LMP_CTYPE_IPV6:
                if (obj_tlen < 36) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
	        ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_data_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));
                ND_PRINT((ndo, "\n\t    Local Interface ID: %s (0x%08x)"
                       "\n\t    Remote Interface ID: %s (0x%08x)",
                       ip6addr_string(ndo, obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                        ip6addr_string(ndo, obj_tptr+20),
                        EXTRACT_32BITS(obj_tptr+20)));
 
		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36))
 		    hexdump=TRUE;
 		break;
 
	    case LMP_CTYPE_UNMD:
                if (obj_tlen < 12) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
	        ND_PRINT((ndo, "\n\t    Flags: [%s]",
		    bittok2str(lmp_obj_data_link_flag_values,
			"none",
			EXTRACT_8BITS(obj_tptr))));
                ND_PRINT((ndo, "\n\t    Local Interface ID: %u (0x%08x)"
                       "\n\t    Remote Interface ID: %u (0x%08x)",
                       EXTRACT_32BITS(obj_tptr+4),
                       EXTRACT_32BITS(obj_tptr+4),
                        EXTRACT_32BITS(obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
 		    hexdump=TRUE;
 		break;
 
            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_VERIFY_BEGIN:
	    switch(lmp_obj_ctype) {
            case LMP_CTYPE_1:
                if (obj_tlen != 20) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Flags: %s",
		bittok2str(lmp_obj_begin_verify_flag_values,
			"none",
			EXTRACT_16BITS(obj_tptr))));
		ND_PRINT((ndo, "\n\t    Verify Interval: %u",
			EXTRACT_16BITS(obj_tptr+2)));
		ND_PRINT((ndo, "\n\t    Data links: %u",
			EXTRACT_32BITS(obj_tptr+4)));
                ND_PRINT((ndo, "\n\t    Encoding type: %s",
			tok2str(gmpls_encoding_values, "Unknown", *(obj_tptr+8))));
                ND_PRINT((ndo, "\n\t    Verify Transport Mechanism: %u (0x%x)%s",
			EXTRACT_16BITS(obj_tptr+10),
			EXTRACT_16BITS(obj_tptr+10),
			EXTRACT_16BITS(obj_tptr+10)&8000 ? " (Payload test messages capable)" : ""));
                bw.i = EXTRACT_32BITS(obj_tptr+12);
		ND_PRINT((ndo, "\n\t    Transmission Rate: %.3f Mbps",bw.f*8/1000000));
		ND_PRINT((ndo, "\n\t    Wavelength: %u",
			EXTRACT_32BITS(obj_tptr+16)));
		break;

            default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_VERIFY_BEGIN_ACK:
	    switch(lmp_obj_ctype) {
            case LMP_CTYPE_1:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Verify Dead Interval: %u"
                       "\n\t    Verify Transport Response: %u",
                       EXTRACT_16BITS(obj_tptr),
                       EXTRACT_16BITS(obj_tptr+2)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

	case LMP_OBJ_VERIFY_ID:
	    switch(lmp_obj_ctype) {
            case LMP_CTYPE_1:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
                ND_PRINT((ndo, "\n\t    Verify ID: %u",
                       EXTRACT_32BITS(obj_tptr)));
                break;

            default:
                hexdump=TRUE;
            }
            break;

	case LMP_OBJ_CHANNEL_STATUS:
            switch(lmp_obj_ctype) {
	    case LMP_CTYPE_IPV4:
		offset = 0;
		/* Decode pairs: <Interface_ID (4 bytes), Channel_status (4 bytes)> */
		while (offset+8 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %s (0x%08x)",
			ipaddr_string(ndo, obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));

			ND_PRINT((ndo, "\n\t\t    Active: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>31) ?
						"Allocated" : "Non-allocated",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>31)));

			ND_PRINT((ndo, "\n\t\t    Direction: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>30)&0x1 ?
						"Transmit" : "Receive",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>30)&0x1));

			ND_PRINT((ndo, "\n\t\t    Channel Status: %s (%u)",
					tok2str(lmp_obj_channel_status_values,
			 		"Unknown",
					EXTRACT_32BITS(obj_tptr+offset+4)&0x3FFFFFF),
			EXTRACT_32BITS(obj_tptr+offset+4)&0x3FFFFFF));
			offset+=8;
		}
                break;

	    case LMP_CTYPE_IPV6:
		offset = 0;
		/* Decode pairs: <Interface_ID (16 bytes), Channel_status (4 bytes)> */
		while (offset+20 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %s (0x%08x)",
			ip6addr_string(ndo, obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));

			ND_PRINT((ndo, "\n\t\t    Active: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+16)>>31) ?
						"Allocated" : "Non-allocated",
				(EXTRACT_32BITS(obj_tptr+offset+16)>>31)));

			ND_PRINT((ndo, "\n\t\t    Direction: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+16)>>30)&0x1 ?
						"Transmit" : "Receive",
				(EXTRACT_32BITS(obj_tptr+offset+16)>>30)&0x1));

			ND_PRINT((ndo, "\n\t\t    Channel Status: %s (%u)",
					tok2str(lmp_obj_channel_status_values,
					"Unknown",
					EXTRACT_32BITS(obj_tptr+offset+16)&0x3FFFFFF),
			EXTRACT_32BITS(obj_tptr+offset+16)&0x3FFFFFF));
			offset+=20;
		}
                break;

	    case LMP_CTYPE_UNMD:
		offset = 0;
		/* Decode pairs: <Interface_ID (4 bytes), Channel_status (4 bytes)> */
		while (offset+8 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %u (0x%08x)",
			EXTRACT_32BITS(obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));

			ND_PRINT((ndo, "\n\t\t    Active: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>31) ?
						"Allocated" : "Non-allocated",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>31)));

			ND_PRINT((ndo, "\n\t\t    Direction: %s (%u)",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>30)&0x1 ?
						"Transmit" : "Receive",
				(EXTRACT_32BITS(obj_tptr+offset+4)>>30)&0x1));

			ND_PRINT((ndo, "\n\t\t    Channel Status: %s (%u)",
					tok2str(lmp_obj_channel_status_values,
					"Unknown",
					EXTRACT_32BITS(obj_tptr+offset+4)&0x3FFFFFF),
			EXTRACT_32BITS(obj_tptr+offset+4)&0x3FFFFFF));
			offset+=8;
		}
                break;

            default:
                hexdump=TRUE;
            }
            break;

	case LMP_OBJ_CHANNEL_STATUS_REQ:
            switch(lmp_obj_ctype) {
	    case LMP_CTYPE_IPV4:
		offset = 0;
		while (offset+4 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %s (0x%08x)",
			ipaddr_string(ndo, obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));
			offset+=4;
		}
                break;

	    case LMP_CTYPE_IPV6:
		offset = 0;
		while (offset+16 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %s (0x%08x)",
			ip6addr_string(ndo, obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));
			offset+=16;
		}
                break;

	    case LMP_CTYPE_UNMD:
		offset = 0;
		while (offset+4 <= obj_tlen) {
			ND_PRINT((ndo, "\n\t    Interface ID: %u (0x%08x)",
			EXTRACT_32BITS(obj_tptr+offset),
			EXTRACT_32BITS(obj_tptr+offset)));
			offset+=4;
		}
                break;

	    default:
                hexdump=TRUE;
            }
            break;

        case LMP_OBJ_ERROR_CODE:
	    switch(lmp_obj_ctype) {
            case LMP_CTYPE_BEGIN_VERIFY_ERROR:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Error Code: %s",
		bittok2str(lmp_obj_begin_verify_error_values,
			"none",
			EXTRACT_32BITS(obj_tptr))));
                break;

            case LMP_CTYPE_LINK_SUMMARY_ERROR:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t    Error Code: %s",
		bittok2str(lmp_obj_link_summary_error_values,
			"none",
			EXTRACT_32BITS(obj_tptr))));
                break;
            default:
                hexdump=TRUE;
            }
            break;

	case LMP_OBJ_SERVICE_CONFIG:
	    switch (lmp_obj_ctype) {
	    case LMP_CTYPE_SERVICE_CONFIG_SP:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }
		ND_PRINT((ndo, "\n\t Flags: %s",
		       bittok2str(lmp_obj_service_config_sp_flag_values,
				  "none",
				  EXTRACT_8BITS(obj_tptr))));

		ND_PRINT((ndo, "\n\t  UNI Version: %u",
		       EXTRACT_8BITS(obj_tptr + 1)));

		break;

            case LMP_CTYPE_SERVICE_CONFIG_CPSA:
                if (obj_tlen != 16) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }

		link_type = EXTRACT_8BITS(obj_tptr);

		ND_PRINT((ndo, "\n\t Link Type: %s (%u)",
		       tok2str(lmp_sd_service_config_cpsa_link_type_values,
			       "Unknown", link_type),
		       link_type));

		switch (link_type) {
		case LMP_SD_SERVICE_CONFIG_CPSA_LINK_TYPE_SDH:
		    ND_PRINT((ndo, "\n\t Signal Type: %s (%u)",
			   tok2str(lmp_sd_service_config_cpsa_signal_type_sdh_values,
				   "Unknown",
				   EXTRACT_8BITS(obj_tptr + 1)),
				   EXTRACT_8BITS(obj_tptr + 1)));
		    break;

		case LMP_SD_SERVICE_CONFIG_CPSA_LINK_TYPE_SONET:
		    ND_PRINT((ndo, "\n\t Signal Type: %s (%u)",
			   tok2str(lmp_sd_service_config_cpsa_signal_type_sonet_values,
				   "Unknown",
				   EXTRACT_8BITS(obj_tptr + 1)),
				   EXTRACT_8BITS(obj_tptr + 1)));
		    break;
		}

		ND_PRINT((ndo, "\n\t Transparency: %s",
		       bittok2str(lmp_obj_service_config_cpsa_tp_flag_values,
				  "none",
				  EXTRACT_8BITS(obj_tptr + 2))));

		ND_PRINT((ndo, "\n\t Contiguous Concatenation Types: %s",
		       bittok2str(lmp_obj_service_config_cpsa_cct_flag_values,
				  "none",
				  EXTRACT_8BITS(obj_tptr + 3))));

		ND_PRINT((ndo, "\n\t Minimum NCC: %u",
		       EXTRACT_16BITS(obj_tptr+4)));

		ND_PRINT((ndo, "\n\t Maximum NCC: %u",
		       EXTRACT_16BITS(obj_tptr+6)));

		ND_PRINT((ndo, "\n\t Minimum NVC:%u",
		       EXTRACT_16BITS(obj_tptr+8)));

		ND_PRINT((ndo, "\n\t Maximum NVC:%u",
		       EXTRACT_16BITS(obj_tptr+10)));

		ND_PRINT((ndo, "\n\t    Local Interface ID: %s (0x%08x)",
		       ipaddr_string(ndo, obj_tptr+12),
		       EXTRACT_32BITS(obj_tptr+12)));

		break;

	    case LMP_CTYPE_SERVICE_CONFIG_TRANSPARENCY_TCM:
                if (obj_tlen != 8) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }

		ND_PRINT((ndo, "\n\t Transparency Flags: %s",
		       bittok2str(
			   lmp_obj_service_config_nsa_transparency_flag_values,
			   "none",
			   EXTRACT_32BITS(obj_tptr))));

		ND_PRINT((ndo, "\n\t TCM Monitoring Flags: %s",
		       bittok2str(
			   lmp_obj_service_config_nsa_tcm_flag_values,
			   "none",
			   EXTRACT_8BITS(obj_tptr + 7))));

		break;

	    case LMP_CTYPE_SERVICE_CONFIG_NETWORK_DIVERSITY:
                if (obj_tlen != 4) {
                    ND_PRINT((ndo, " (not correct for object)"));
                    break;
                }

		ND_PRINT((ndo, "\n\t Diversity: Flags: %s",
		       bittok2str(
			   lmp_obj_service_config_nsa_network_diversity_flag_values,
			   "none",
			   EXTRACT_8BITS(obj_tptr + 3))));
		break;

	    default:
		hexdump = TRUE;
	    }

	break;

        default:
            if (ndo->ndo_vflag <= 1)
                print_unknown_data(ndo,obj_tptr,"\n\t    ",obj_tlen);
            break;
        }
        /* do we want to see an additionally hexdump ? */
        if (ndo->ndo_vflag > 1 || hexdump==TRUE)
            print_unknown_data(ndo,tptr+sizeof(struct lmp_object_header),"\n\t    ",
                               lmp_obj_len-sizeof(struct lmp_object_header));

        tptr+=lmp_obj_len;
        tlen-=lmp_obj_len;
    }
    return;
trunc:
    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **4**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `print-lmp.c` **(funcao marcada esta aqui)** | modified | 16 | 4 |
| `tests/TESTLIST` | modified | 1 | 0 |
| `tests/lmp-lmp_print_data_link_subobjs-oobr.out` | added | 22 | 0 |
| `tests/lmp-lmp_print_data_link_subobjs-oobr.pcap` | added | 0 | 0 |


### `print-lmp.c`

```diff
@@ -399,6 +399,7 @@ lmp_print_data_link_subobjs(netdissect_options *ndo, const u_char *obj_tptr,
 			"Unknown",
 			EXTRACT_8BITS(obj_tptr + offset + 3)),
 			EXTRACT_8BITS(obj_tptr + offset + 3)));
+	    ND_TCHECK_32BITS(obj_tptr + offset + 4);
 	    bw.i = EXTRACT_32BITS(obj_tptr+offset+4);
 	    ND_PRINT((ndo, "\n\t      Min Reservable Bandwidth: %.3f Mbps",
                 bw.f*8/1000000));
@@ -419,6 +420,8 @@ lmp_print_data_link_subobjs(netdissect_options *ndo, const u_char *obj_tptr,
 	offset+=subobj_len;
     }
     return (hexdump);
+trunc:
+    return -1;
 }
 
 void
@@ -429,7 +432,7 @@ lmp_print(netdissect_options *ndo,
     const struct lmp_object_header *lmp_obj_header;
     const u_char *tptr,*obj_tptr;
     u_int tlen,lmp_obj_len,lmp_obj_ctype,obj_tlen;
-    int hexdump;
+    int hexdump, ret;
     u_int offset;
     u_int link_type;
 
@@ -731,7 +734,10 @@ lmp_print(netdissect_options *ndo,
                        ipaddr_string(ndo, obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
@@ -751,7 +757,10 @@ lmp_print(netdissect_options *ndo,
                        ip6addr_string(ndo, obj_tptr+20),
                        EXTRACT_32BITS(obj_tptr+20)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
@@ -771,7 +780,10 @@ lmp_print(netdissect_options *ndo,
                        EXTRACT_32BITS(obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
```


### `tests/TESTLIST`

```diff
@@ -560,6 +560,7 @@ vrrp-vrrp_print-oobr vrrp-vrrp_print-oobr.pcap vrrp-vrrp_print-oobr.out -v -c3
 vrrp-vrrp_print-oobr-2 vrrp-vrrp_print-oobr-2.pcap vrrp-vrrp_print-oobr-2.out -v
 bgp-bgp_capabilities_print-oobr-1 bgp-bgp_capabilities_print-oobr-1.pcap bgp-bgp_capabilities_print-oobr-1.out -v -c1
 bgp-bgp_capabilities_print-oobr-2 bgp-bgp_capabilities_print-oobr-2.pcap bgp-bgp_capabilities_print-oobr-2.out -v -c1
+lmp-lmp_print_data_link_subobjs-oobr lmp-lmp_print_data_link_subobjs-oobr.pcap lmp-lmp_print_data_link_subobjs-oobr.out -v -c2
 # The .pcap file is truncated after the 1st packet.
 hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
 hncp_dhcpv4data-oobr	hncp_dhcpv4data-oobr.pcap	hncp_dhcpv4data-oobr.out -v -c1
```


### `tests/lmp-lmp_print_data_link_subobjs-oobr.out`

```diff
@@ -0,0 +1,22 @@
+IP (tos 0xfd,ECT(1), ttl 254, id 45839, offset 0, flags [+, DF, rsvd], proto UDP (17), length 56871, bad cksum fe07 (->ddf0)!)
+    17.8.8.255.701 > 40.184.42.8.12: 
+	LMPv1, msg-type: unknown, type: 249, Flags: [none], length: 212
+	  Data Link Object (12), Class-Type: Unnumbered (3) Flags: [non-negotiable], length: 20
+	    Flags: [none]
+	    Local Interface ID: 2435832538 (0x912fdada)
+	    Remote Interface ID: 3657433088 (0xda000000)
+	    Subobject, Type: Interface Switching Type (1), Length: 4
+	      Switching Type: Unknown (0)
+	      Encoding Type: Unknown (0)
+		 packet exceeded snapshot
+IP (tos 0xfd,ECT(1), ttl 254, id 45839, offset 0, flags [+, DF, rsvd], proto UDP (17), length 56871, bad cksum fe07 (->ddf0)!)
+    17.8.8.255.701 > 40.184.42.8.12: 
+	LMPv1, msg-type: unknown, type: 249, Flags: [none], length: 212
+	  Data Link Object (12), Class-Type: Unnumbered (3) Flags: [non-negotiable], length: 20
+	    Flags: [none]
+	    Local Interface ID: 2435832538 (0x912fdada)
+	    Remote Interface ID: 3657433088 (0xda000000)
+	    Subobject, Type: Interface Switching Type (1), Length: 4
+	      Switching Type: Unknown (0)
+	      Encoding Type: Unknown (0)
+		 packet exceeded snapshot
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
