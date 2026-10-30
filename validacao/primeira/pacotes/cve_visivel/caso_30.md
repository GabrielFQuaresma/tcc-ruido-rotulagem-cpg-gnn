# Pacote de anotacao — caso 30

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

# Evidencia do caso 30

## Identificacao

- projeto: OpenSC
- CVE: CVE-2018-16427
- CWE atribuida pelo BigVul: CWE-125
- commit: `8fe377e93b4b56060e5bbfb6f3142ceaeca744fa`
- URL do commit: https://github.com/OpenSC/OpenSC/pull/1447/commits/8fe377e93b4b56060e5bbfb6f3142ceaeca744fa
- arquivo da funcao marcada: `src/libopensc/card-authentic.c`

## Mensagem do commit

> fixed out of bounds reads
> 
> Thanks to Eric Sesterhenn from X41 D-SEC GmbH
> for reporting and suggesting security fixes.

## Resumo da CVE

> Various out of bounds reads when handling responses in OpenSC before 0.19.0-rc1 could be used by attackers able to supply crafted smartcards to potentially crash the opensc library using programs.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -44,7 +44,7 @@
  	}
  
  	sc_log_hex(ctx, "ACL data", file->sec_attr, file->sec_attr_len);
-	for (ii = 0; ii < file->sec_attr_len / 2; ii++)  {
+	for (ii = 0; ii < file->sec_attr_len / 2 && ii < sizeof ops_DF; ii++)  {
  		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];
  		unsigned char acl = *(file->sec_attr + ii*2);
  		unsigned char cred_id = *(file->sec_attr + ii*2 + 1);
```

## Corpo completo da funcao antes da correcao

```c
authentic_process_fci(struct sc_card *card, struct sc_file *file,
		 const unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen;
	int rv;
	unsigned ii;
	const unsigned char *tag = NULL;
	unsigned char ops_DF[8] = {
		SC_AC_OP_CREATE, SC_AC_OP_DELETE, SC_AC_OP_CRYPTO, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};
	unsigned char ops_EF[8] = {
		SC_AC_OP_READ, SC_AC_OP_DELETE, SC_AC_OP_UPDATE, SC_AC_OP_RESIZE, 0xFF, 0xFF, 0xFF, 0xFF
	};

	LOG_FUNC_CALLED(ctx);

	tag = sc_asn1_find_tag(card->ctx,  buf, buflen, 0x6F, &taglen);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	tag = sc_asn1_find_tag(card->ctx,  buf, buflen, 0x62, &taglen);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	rv = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(ctx, rv, "ISO parse FCI failed");

	if (!file->sec_attr_len)   {
		sc_log_hex(ctx, "ACLs not found in data", buf, buflen);
		sc_log(ctx, "Path:%s; Type:%X; PathType:%X", sc_print_path(&file->path), file->type, file->path.type);
		if (file->path.type == SC_PATH_TYPE_DF_NAME || file->type == SC_FILE_TYPE_DF)   {
			file->type = SC_FILE_TYPE_DF;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "ACLs tag missing");
		}
 	}
 
 	sc_log_hex(ctx, "ACL data", file->sec_attr, file->sec_attr_len);
	for (ii = 0; ii < file->sec_attr_len / 2; ii++)  {
 		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];
 		unsigned char acl = *(file->sec_attr + ii*2);
 		unsigned char cred_id = *(file->sec_attr + ii*2 + 1);
		unsigned sc = acl * 0x100 + cred_id;

		sc_log(ctx, "ACL(%i) op 0x%X, acl %X:%X", ii, op, acl, cred_id);
		if (op == 0xFF)
			;
		else if (!acl && !cred_id)
			sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
		else if (acl == 0xFF)
			sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
		else if (acl & AUTHENTIC_AC_SM_MASK)
			sc_file_add_acl_entry(file, op, SC_AC_SCB, sc);
		else if (cred_id)
			sc_file_add_acl_entry(file, op, SC_AC_CHV, cred_id);
		else
			sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
	}

	LOG_FUNC_RETURN(ctx, 0);
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **18**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/libopensc/asn1.c` | modified | 1 | 0 |
| `src/libopensc/card-asepcos.c` | modified | 1 | 1 |
| `src/libopensc/card-authentic.c` **(funcao marcada esta aqui)** | modified | 4 | 1 |
| `src/libopensc/card-cac.c` | modified | 7 | 2 |
| `src/libopensc/card-coolkey.c` | modified | 1 | 1 |
| `src/libopensc/card-entersafe.c` | modified | 5 | 3 |
| `src/libopensc/card-epass2003.c` | modified | 19 | 16 |
| `src/libopensc/card-gpk.c` | modified | 3 | 0 |
| `src/libopensc/card-iasecc.c` | modified | 1 | 1 |
| `src/libopensc/card-oberthur.c` | modified | 7 | 0 |
| `src/libopensc/card-openpgp.c` | modified | 6 | 0 |
| `src/libopensc/card-piv.c` | modified | 5 | 4 |
| `src/libopensc/card-rtecp.c` | modified | 1 | 1 |
| `src/libopensc/card-setcos.c` | modified | 16 | 2 |
| `src/libopensc/ef-gdo.c` | modified | 1 | 1 |
| `src/libopensc/pkcs15-itacns.c` | modified | 1 | 0 |
| `src/libopensc/pkcs15-tcos.c` | modified | 5 | 3 |
| `src/tools/opensc-tool.c` | modified | 11 | 10 |


### `src/libopensc/card-authentic.c`

```diff
@@ -560,6 +560,9 @@ authentic_set_current_files(struct sc_card *card, struct sc_path *path,
 			sc_file_dup(&card->cache.current_df, file);
 
 			if (cur_df_path.len)   {
+				if (cur_df_path.len + card->cache.current_df->path.len > sizeof card->cache.current_df->path.value
+						|| cur_df_path.len > sizeof card->cache.current_df->path.value)
+					LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
 				memcpy(card->cache.current_df->path.value + cur_df_path.len,
 						card->cache.current_df->path.value,
 						card->cache.current_df->path.len);
@@ -988,7 +991,7 @@ authentic_process_fci(struct sc_card *card, struct sc_file *file,
 	}
 
 	sc_log_hex(ctx, "ACL data", file->sec_attr, file->sec_attr_len);
-	for (ii = 0; ii < file->sec_attr_len / 2; ii++)  {
+	for (ii = 0; ii < file->sec_attr_len / 2 && ii < sizeof ops_DF; ii++)  {
 		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];
 		unsigned char acl = *(file->sec_attr + ii*2);
 		unsigned char cred_id = *(file->sec_attr + ii*2 + 1);
```


### `src/libopensc/asn1.c`

```diff
@@ -103,6 +103,7 @@ int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
 	len = *p & 0x7f;
 	if (*p++ & 0x80) {
 		unsigned int a = 0;
+		left--;
 		if (len > 4 || len > left)
 			return SC_ERROR_INVALID_ASN1_OBJECT;
 		left -= len;
```


### `src/libopensc/card-asepcos.c`

```diff
@@ -169,7 +169,7 @@ static int asepcos_parse_sec_attr(sc_card_t *card, sc_file_t *file, const u8 *bu
 
 	while (len != 0) {
 		unsigned int amode, tlen = 3;
-		if (len < 5 && p[0] != 0x80 && p[1] != 0x01) {
+		if (len < 5 || p[0] != 0x80 || p[1] != 0x01) {
 			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid access mode encoding");
 			return SC_ERROR_INTERNAL;
 		}
```


### `src/libopensc/card-cac.c`

```diff
@@ -664,12 +664,17 @@ static int cac_read_binary(sc_card_t *card, unsigned int idx,
 		cert_len = 0;
 		cert_ptr = NULL;
 		cert_type = 0;
-		for (tl_ptr = tl, val_ptr=val; tl_len >= 2;
-				val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
+		for (tl_ptr = tl, val_ptr = val; tl_len >= 2;
+		    val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
 			tl_start = tl_ptr;
 			if (sc_simpletlv_read_tag(&tl_ptr, tl_len, &tag, &len) != SC_SUCCESS)
 				break;
 			tl_head_len = tl_ptr - tl_start;
+
+			/* incomplete value */
+			if (val_len < len)
+				break;
+
 			if (tag == CAC_TAG_CERTIFICATE) {
 				cert_len = len;
 				cert_ptr = val_ptr;
```


### `src/libopensc/card-coolkey.c`

```diff
@@ -1467,7 +1467,7 @@ coolkey_find_attribute(sc_card_t *card, sc_cardctl_coolkey_attribute_t *attribut
 	for (i=0; i < attribute_count; i++) {
 		size_t record_len = coolkey_get_attribute_record_len(attr, object_record_type, buf_len);
 		/* make sure we have the complete record */
-		if (buf_len < record_len) {
+		if (buf_len < record_len || record_len < 4) {
 				return SC_ERROR_CORRUPTED_DATA;
 		}
 		/* does the attribute match the one we are looking for */
```


### `src/libopensc/card-entersafe.c`

```diff
@@ -1408,13 +1408,15 @@ static int entersafe_gen_key(sc_card_t *card, sc_entersafe_gen_key_data *data)
 
 	data->modulus = malloc(len);
 	if (!data->modulus)
-		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_OUT_OF_MEMORY);
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);
 
 	p=rbuf;
-	assert(*p=='E');
+	if (*p!='E')
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);
 	p+=2+p[1];
 	/* N */
-	assert(*p=='N');
+	if (*p!='N')
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);
 	++p;
 	if(*p++>0x80)
 	{
```


### `src/libopensc/card-epass2003.c`

```diff
@@ -740,11 +740,11 @@ construct_mac_tlv(struct sc_card *card, unsigned char *apdu_buf, size_t data_tlv
 		memcpy(mac_tlv + 2, &mac[mac_len - 16], 8);
 	}
 	else {
-		unsigned char iv[8] = { 0 };
+		unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
 		unsigned char tmp[8] = { 0 };
 		des_encrypt_cbc(exdata->sk_mac, 8, icv, apdu_buf, mac_len, mac);
 		des_decrypt_cbc(&exdata->sk_mac[8], 8, iv, &mac[mac_len - 8], 8, tmp);
-		memset(iv, 0x00, 8);
+		memset(iv, 0x00, sizeof iv);
 		des_encrypt_cbc(exdata->sk_mac, 8, iv, tmp, 8, mac_tlv + 2);
 	}
 
@@ -903,9 +903,9 @@ epass2003_sm_wrap_apdu(struct sc_card *card, struct sc_apdu *plain, struct sc_ap
  * SW12(TLV)=0x99|0x02|SW1+SW2
  * MAC(TLV)=0x8e|0x08|MAC */
 static int
-decrypt_response(struct sc_card *card, unsigned char *in, unsigned char *out, size_t * out_len)
+decrypt_response(struct sc_card *card, unsigned char *in, size_t inlen, unsigned char *out, size_t * out_len)
 {
-	size_t in_len;
+	size_t cipher_len;
 	size_t i;
 	unsigned char iv[16] = { 0 };
 	unsigned char plaintext[4096] = { 0 };
@@ -922,37 +922,40 @@ decrypt_response(struct sc_card *card, unsigned char *in, unsigned char *out, si
 
 	/* parse cipher length */
 	if (0x01 == in[2] && 0x82 != in[1]) {
-		in_len = in[1];
+		cipher_len = in[1];
 		i = 3;
 	}
 	else if (0x01 == in[3] && 0x81 == in[1]) {
-		in_len = in[2];
+		cipher_len = in[2];
 		i = 4;
 	}
 	else if (0x01 == in[4] && 0x82 == in[1]) {
-		in_len = in[2] * 0x100;
-		in_len += in[3];
+		cipher_len = in[2] * 0x100;
+		cipher_len += in[3];
 		i = 5;
 	}
 	else {
 		return -1;
 	}
 
+	if (cipher_len < 2 || i+cipher_len > inlen || cipher_len > sizeof plaintext)
+		return -1;
+
 	/* decrypt */
 	if (KEY_TYPE_AES == exdata->smtype)
-		aes128_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], in_len - 1, plaintext);
+		aes128_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);
 	else
-		des3_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], in_len - 1, plaintext);
+		des3_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);
 
 	/* unpadding */
-	while (0x80 != plaintext[in_len - 2] && (in_len - 2 > 0))
-		in_len--;
+	while (0x80 != plaintext[cipher_len - 2] && (cipher_len - 2 > 0))
+		cipher_len--;
 
-	if (2 == in_len)
+	if (2 == cipher_len)
 		return -1;
 
-	memcpy(out, plaintext, in_len - 2);
-	*out_len = in_len - 2;
+	memcpy(out, plaintext, cipher_len - 2);
+	*out_len = cipher_len - 2;
 	return 0;
 }
 
@@ -974,7 +977,7 @@ epass2003_sm_unwrap_apdu(struct sc_card *card, struct sc_apdu *sm, struct sc_apd
 	r = sc_check_sw(card, sm->sw1, sm->sw2);
 	if (r == SC_SUCCESS) {
 		if (exdata->sm) {
-			if (0 != decrypt_response(card, sm->resp, plain->resp, &len))
+			if (0 != decrypt_response(card, sm->resp, sm->resplen, plain->resp, &len))
 				return SC_ERROR_CARD_CMD_FAILED;
 		}
 		else {
```


### `src/libopensc/card-gpk.c`

```diff
@@ -409,6 +409,9 @@ gpk_parse_fileinfo(sc_card_t *card,
 		if (sp[0] == 0x85) {
 			unsigned int	ac[3], n;
 
+			if (sp + 11 + 2*3 >= end)
+				break;
+
 			file->id = (sp[4] << 8) | sp[5];
 			file->size = (sp[8] << 8) | sp[9];
 			file->record_length = sp[7];
```


### `src/libopensc/card-iasecc.c`

```diff
@@ -2548,7 +2548,7 @@ iasecc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
 	if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
 		/* 5A 0A 92 50 00 20 10 10 25 00 01 3F */
 		/*            00 02 01 01 02 50 00 13  */
-		for (ii=0; ii < rbuf[1] - offs; ii++)
+		for (ii=0; (ii < rbuf[1] - offs) && (ii + offs + 2 < sizeof(rbuf)); ii++)
 			*(card->serialnr.value + ii) = ((rbuf[ii + offs + 1] & 0x0F) << 4)
 				+ ((rbuf[ii + offs + 2] & 0xF0) >> 4) ;
 		card->serialnr.len = ii;
```


### `src/libopensc/card-oberthur.c`

```diff
@@ -476,6 +476,9 @@ auth_select_file(struct sc_card *card, const struct sc_path *in_path,
 
 	memcpy(&path, in_path, sizeof(struct sc_path));
 
+	if (!auth_current_df)
+		return SC_ERROR_OBJECT_NOT_FOUND;
+
 	sc_log(card->ctx, "in_path; type=%d, path=%s, out %p",
 			in_path->type, sc_print_path(in_path), file_out);
 	sc_log(card->ctx, "current path; type=%d, path=%s",
@@ -2113,6 +2116,10 @@ auth_read_binary(struct sc_card *card, unsigned int offset,
 	bn[1].data = NULL;
 
 	LOG_FUNC_CALLED(card->ctx);
+
+	if (!auth_current_ef)
+		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid auth_current_ef");
+
 	sc_log(card->ctx,
 	       "offset %i; size %"SC_FORMAT_LEN_SIZE_T"u; flags 0x%lX",
 	       offset, count, flags);
```


### `src/libopensc/card-openpgp.c`

```diff
@@ -1061,6 +1061,9 @@ pgp_enumerate_blob(sc_card_t *card, pgp_blob_t *blob)
 		const u8	*data = in;
 		pgp_blob_t	*new;
 
+		if (!in)
+			return SC_ERROR_OBJECT_NOT_VALID;
+
 		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
 					&cla, &tag, &len);
 		if (r < 0 || data == NULL) {
@@ -1069,6 +1072,9 @@ pgp_enumerate_blob(sc_card_t *card, pgp_blob_t *blob)
 			return SC_ERROR_OBJECT_NOT_VALID;
 		}
 
+		if (data + len > blob->data + blob->len)
+			return SC_ERROR_OBJECT_NOT_VALID;
+
 		/* undo ASN1's split of tag & class */
 		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
 			cla <<= 8;
```


### `src/libopensc/card-piv.c`

```diff
@@ -573,7 +573,7 @@ static int piv_general_io(sc_card_t *card, int ins, int p1, int p2,
 		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */
 
 		body = rbuf;
-		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS
+		if (sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS
 				|| body == NULL)  {
 			/* only early beta cards had this problem */
 			sc_log(card->ctx, "***** received buffer tag MISSING ");
@@ -3033,12 +3033,13 @@ static int piv_match_card_continued(sc_card_t *card)
 			 *   73 66 74 65 20 63 64 31 34 34
 			 * will check for 73 66 74 65
 			 */
-			else if (card->reader->atr_info.hist_bytes_len >= 4 &&
-					!(memcmp(card->reader->atr_info.hist_bytes, "sfte", 4))) {
+			else if (card->reader->atr_info.hist_bytes_len >= 4
+					&& !(memcmp(card->reader->atr_info.hist_bytes, "sfte", 4))) {
 				type = SC_CARD_TYPE_PIV_II_GI_DE;
 			}
 
-			else if (card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
+			else if (card->reader->atr_info.hist_bytes_len > 0
+					&& card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
 				size_t datalen;
 				const u8 *data = sc_compacttlv_find_tag(card->reader->atr_info.hist_bytes + 1,
 									card->reader->atr_info.hist_bytes_len - 1,
```


### `src/libopensc/card-rtecp.c`

```diff
@@ -275,7 +275,7 @@ static int rtecp_select_file(sc_card_t *card,
 		set_acl_from_sec_attr(card, file);
 	else
 		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
-	if (r)
+	if (r && !file_out)
 		sc_file_free(file);
 	else
 	{
```


### `src/libopensc/card-setcos.c`

```diff
@@ -789,6 +789,8 @@ static void parse_sec_attr_44(sc_file_t *file, const u8 *buf, size_t len)
 	/* Check all sub-AC definitions within the total AC */
 	while (len > 1) {				/* minimum length = 2 */
 		int	iACLen   = buf[iOffset] & 0x0F;
+		if ((size_t) iACLen > len)
+			break;
 
 		iPinCount = -1;			/* default no pin required */
 		iMethod = SC_AC_NONE;		/* default no authentication required */
@@ -806,7 +808,10 @@ static void parse_sec_attr_44(sc_file_t *file, const u8 *buf, size_t len)
 
 			/* Get KeyNumber if available */
 			if(iKeyLen) {
-				int iSC = buf[iOffset+iACLen];
+				int iSC;
+				if (len < 1+iACLen)
+					break;
+				iSC = buf[iOffset+iACLen];
 
 				switch( (iSC>>5) & 0x03 ){
 				case 0:
@@ -825,11 +830,15 @@ static void parse_sec_attr_44(sc_file_t *file, const u8 *buf, size_t len)
 
 			/* Get PinNumber if available */
 			if (iACLen > (1+iParmLen+iKeyLen)) {  /* check via total length if pin is present */
+				if (len < 1+1+1+iParmLen)
+					break;
 				iKeyRef = buf[iOffset+1+1+iParmLen];  /* PTL + AM-header + parameter-bytes */
 				iMethod = SC_AC_CHV;
 			}
 
 			/* Convert SETCOS command to OpenSC command group */
+			if (len < 1+2)
+				break;
 			switch(buf[iOffset+2]){
 			case 0x2A:			/* crypto operation */
 				iOperation = SC_AC_OP_CRYPTO;
@@ -863,7 +872,10 @@ static void parse_sec_attr_44(sc_file_t *file, const u8 *buf, size_t len)
 			iPinCount = iACLen - 1;		
 
 			if (buf[iOffset] & 0x20) {
-				int iSC = buf[iOffset + iACLen];
+				int iSC;
+				if (len < 1 + iACLen)
+					break;
+				iSC = buf[iOffset + iACLen];
 
 				switch( (iSC>>5) & 0x03 ) {
 				case 0:
@@ -884,6 +896,8 @@ static void parse_sec_attr_44(sc_file_t *file, const u8 *buf, size_t len)
 
 			/* Pin present ? */
 			if ( iPinCount > 0 ) {
+				if (len < 1 + 2)
+					break;
 				iKeyRef = buf[iOffset + 2];	/* pin ref */
 				iMethod = SC_AC_CHV;
 			}
```


### `src/libopensc/ef-gdo.c`

```diff
@@ -72,7 +72,7 @@ sc_parse_ef_gdo_content(const unsigned char *gdo, size_t gdo_len,
 		}
 
 		p += tag_len;
-		left -= (p - gdo);
+		left = gdo_len - (p - gdo);
 	}
 
 	if (!iccsn_found && iccsn_len)
```


### `src/libopensc/pkcs15-itacns.c`

```diff
@@ -550,6 +550,7 @@ static int itacns_add_data_files(sc_pkcs15_card_t *p15card)
 		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
 			"Could not read EF_DatiPersonali: "
 			"keeping generic card name");
+		return SC_SUCCESS;
 	}
 
 	{
```


### `src/libopensc/pkcs15-tcos.c`

```diff
@@ -132,7 +132,7 @@ static int insert_key(
 		int i, rec_no=0;
 		if(prkey_info.path.len>=2) prkey_info.path.len-=2;
 		sc_append_file_id(&prkey_info.path, 0x5349);
-		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS){
+		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS || !f->prop_attr){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
 				"Select(%s) failed\n",
 				sc_print_path(&prkey_info.path));
@@ -157,7 +157,8 @@ static int insert_key(
 			if(buf[i]==0xB8) can_crypt++;
 		}
 	} else {
-		if(sc_select_file(card, &prkey_info.path, &f)!=SC_SUCCESS){
+		if(sc_select_file(card, &prkey_info.path, &f)!=SC_SUCCESS
+			   	|| !f->prop_attr || f->prop_attr_len < 2){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
 				"Select(%s) failed\n",
 				sc_print_path(&prkey_info.path));
@@ -245,7 +246,8 @@ static int insert_pin(
 			return 1;
 		}
 	} else {
-		if(sc_select_file(card, &pin_info.path, &f)!=SC_SUCCESS){
+		if(sc_select_file(card, &pin_info.path, &f)!=SC_SUCCESS
+			   	|| !f->prop_attr || f->prop_attr_len < 4){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,"Select(%s) failed\n", path);
 			return 1;
 		}
```


### `src/tools/opensc-tool.c`

```diff
@@ -457,7 +457,7 @@ static int enum_dir(sc_path_t path, int depth)
 {
 	sc_file_t *file;
 	int r, file_type;
-	u8 files[SC_MAX_APDU_BUFFER_SIZE];
+	u8 files[SC_MAX_EXT_APDU_BUFFER_SIZE];
 
 	r = sc_lock(card);
 	if (r == SC_SUCCESS)
@@ -483,15 +483,16 @@ static int enum_dir(sc_path_t path, int depth)
 		}
 		if (r == 0) {
 			printf("Empty directory\n");
-		} else
-		for (i = 0; i < r/2; i++) {
-			sc_path_t tmppath;
-
-			memset(&tmppath, 0, sizeof(tmppath));
-			memcpy(&tmppath, &path, sizeof(path));
-			memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
-			tmppath.len += 2;
-			enum_dir(tmppath, depth + 1);
+		} else {
+			for (i = 0; i < r/2; i++) {
+				sc_path_t tmppath;
+
+				memset(&tmppath, 0, sizeof(tmppath));
+				memcpy(&tmppath, &path, sizeof(path));
+				memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
+				tmppath.len += 2;
+				enum_dir(tmppath, depth + 1);
+			}
 		}
 	}
 	return 0;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
