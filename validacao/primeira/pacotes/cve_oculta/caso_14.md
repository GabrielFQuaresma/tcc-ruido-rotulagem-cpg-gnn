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

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-125
- arquivo da funcao marcada: `minissdpd/minissdpd.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -28,7 +28,7 @@
  	type = buf[0];
  	p = buf + 1;
  	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-	if(p+l > buf+n) {
+	if(l > (unsigned)(buf+n-p)) {
  		syslog(LOG_WARNING, "bad request (length encoding l=%u n=%u)",
  		       l, (unsigned)n);
  		goto error;
@@ -150,7 +150,7 @@
  			goto error;
  		}
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
@@ -168,7 +168,7 @@
  		newserv->usn[l] = '\0';
  		p += l;
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
@@ -186,7 +186,7 @@
  		newserv->server[l] = '\0';
  		p += l;
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
```

## Corpo completo da funcao antes da correcao

```c
void processRequest(struct reqelem * req)
{
	ssize_t n;
	unsigned int l, m;
	unsigned char buf[2048];
	const unsigned char * p;
	enum request_type type;
	struct device * d = devlist;
	unsigned char rbuf[RESPONSE_BUFFER_SIZE];
	unsigned char * rp;
	unsigned char nrep = 0;
	time_t t;
	struct service * newserv = NULL;
	struct service * serv;

	n = read(req->socket, buf, sizeof(buf));
	if(n<0) {
		if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;	/* try again later */
		syslog(LOG_ERR, "(s=%d) processRequest(): read(): %m", req->socket);
		goto error;
	}
	if(n==0) {
		syslog(LOG_INFO, "(s=%d) request connection closed", req->socket);
		goto error;
	}
	t = time(NULL);
 	type = buf[0];
 	p = buf + 1;
 	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
	if(p+l > buf+n) {
 		syslog(LOG_WARNING, "bad request (length encoding l=%u n=%u)",
 		       l, (unsigned)n);
 		goto error;
	}
	if(l == 0 && type != MINISSDPD_SEARCH_ALL
	   && type != MINISSDPD_GET_VERSION && type != MINISSDPD_NOTIF) {
		syslog(LOG_WARNING, "bad request (length=0, type=%d)", type);
		goto error;
	}
	syslog(LOG_INFO, "(s=%d) request type=%d str='%.*s'",
	       req->socket, type, l, p);
	switch(type) {
	case MINISSDPD_GET_VERSION:
		rp = rbuf;
		CODELENGTH((sizeof(MINISSDPD_VERSION) - 1), rp);
		memcpy(rp, MINISSDPD_VERSION, sizeof(MINISSDPD_VERSION) - 1);
		rp += (sizeof(MINISSDPD_VERSION) - 1);
		if(write_or_buffer(req, rbuf, rp - rbuf) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
		break;
	case MINISSDPD_SEARCH_TYPE:	/* request by type */
	case MINISSDPD_SEARCH_USN:	/* request by USN (unique id) */
	case MINISSDPD_SEARCH_ALL:	/* everything */
		rp = rbuf+1;
		while(d && (nrep < 255)) {
			if(d->t < t) {
				syslog(LOG_INFO, "outdated device");
			} else {
				/* test if we can put more responses in the buffer */
				if(d->headers[HEADER_LOCATION].l + d->headers[HEADER_NT].l
				  + d->headers[HEADER_USN].l + 6
				  + (rp - rbuf) >= (int)sizeof(rbuf))
					break;
				if( (type==MINISSDPD_SEARCH_TYPE && 0==memcmp(d->headers[HEADER_NT].p, p, l))
				  ||(type==MINISSDPD_SEARCH_USN && 0==memcmp(d->headers[HEADER_USN].p, p, l))
				  ||(type==MINISSDPD_SEARCH_ALL) ) {
					/* response :
					 * 1 - Location
					 * 2 - NT (device/service type)
					 * 3 - usn */
					m = d->headers[HEADER_LOCATION].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_LOCATION].p, d->headers[HEADER_LOCATION].l);
					rp += d->headers[HEADER_LOCATION].l;
					m = d->headers[HEADER_NT].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_NT].p, d->headers[HEADER_NT].l);
					rp += d->headers[HEADER_NT].l;
					m = d->headers[HEADER_USN].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_USN].p, d->headers[HEADER_USN].l);
					rp += d->headers[HEADER_USN].l;
					nrep++;
				}
			}
			d = d->next;
		}
		/* Also look in service list */
		for(serv = servicelisthead.lh_first;
		    serv && (nrep < 255);
		    serv = serv->entries.le_next) {
			/* test if we can put more responses in the buffer */
			if(strlen(serv->location) + strlen(serv->st)
			  + strlen(serv->usn) + 6 + (rp - rbuf) >= sizeof(rbuf))
			  	break;
			if( (type==MINISSDPD_SEARCH_TYPE && 0==strncmp(serv->st, (const char *)p, l))
			  ||(type==MINISSDPD_SEARCH_USN && 0==strncmp(serv->usn, (const char *)p, l))
			  ||(type==MINISSDPD_SEARCH_ALL) ) {
				/* response :
				 * 1 - Location
				 * 2 - NT (device/service type)
				 * 3 - usn */
				m = strlen(serv->location);
				CODELENGTH(m, rp);
				memcpy(rp, serv->location, m);
				rp += m;
				m = strlen(serv->st);
				CODELENGTH(m, rp);
				memcpy(rp, serv->st, m);
				rp += m;
				m = strlen(serv->usn);
				CODELENGTH(m, rp);
				memcpy(rp, serv->usn, m);
				rp += m;
				nrep++;
			}
		}
		rbuf[0] = nrep;
		syslog(LOG_DEBUG, "(s=%d) response : %d device%s",
		       req->socket, nrep, (nrep > 1) ? "s" : "");
		if(write_or_buffer(req, rbuf, rp - rbuf) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
		break;
	case MINISSDPD_SUBMIT:	/* submit service */
		newserv = malloc(sizeof(struct service));
		if(!newserv) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memset(newserv, 0, sizeof(struct service));	/* set pointers to NULL */
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (st contains forbidden chars)");
			goto error;
		}
		newserv->st = malloc(l + 1);
		if(!newserv->st) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->st, p, l);
		newserv->st[l] = '\0';
		p += l;
		if(p >= buf + n) {
			syslog(LOG_WARNING, "bad request (missing usn)");
 			goto error;
 		}
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (usn contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "usn='%.*s'", l, p);
		newserv->usn = malloc(l + 1);
		if(!newserv->usn) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->usn, p, l);
 		newserv->usn[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (server contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "server='%.*s'", l, p);
		newserv->server = malloc(l + 1);
		if(!newserv->server) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->server, p, l);
 		newserv->server[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (location contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "location='%.*s'", l, p);
		newserv->location = malloc(l + 1);
		if(!newserv->location) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->location, p, l);
		newserv->location[l] = '\0';
		/* look in service list for duplicate */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strcmp(newserv->usn, serv->usn)
			  && 0 == strcmp(newserv->st, serv->st)) {
				syslog(LOG_INFO, "Service already in the list. Updating...");
				free(newserv->st);
				free(newserv->usn);
				free(serv->server);
				serv->server = newserv->server;
				free(serv->location);
				serv->location = newserv->location;
				free(newserv);
				newserv = NULL;
				return;
			}
		}
		/* Inserting new service */
		LIST_INSERT_HEAD(&servicelisthead, newserv, entries);
		sendNotifications(NOTIF_NEW, NULL, newserv);
		newserv = NULL;
		break;
	case MINISSDPD_NOTIF:	/* switch socket to notify */
		rbuf[0] = '\0';
		if(write_or_buffer(req, rbuf, 1) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
		req->is_notify = 1;
		break;
	default:
		syslog(LOG_WARNING, "Unknown request type %d", type);
		rbuf[0] = '\0';
		if(write_or_buffer(req, rbuf, 1) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
	}
	return;
error:
	if(newserv) {
		free(newserv->st);
		free(newserv->usn);
		free(newserv->server);
		free(newserv->location);
		free(newserv);
		newserv = NULL;
	}
	close(req->socket);
	req->socket = -1;
	return;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `minissdpd/Changelog.txt` | modified | 4 | 1 |
| `minissdpd/minissdpd.c` **(funcao marcada esta aqui)** | modified | 5 | 5 |
| `minissdpd/testminissdpd.c` | modified | 11 | 1 |


### `minissdpd/minissdpd.c`

```diff
@@ -1,4 +1,4 @@
-/* $Id: minissdpd.c,v 1.50 2015/08/06 14:05:49 nanard Exp $ */
+/* $Id: minissdpd.c,v 1.53 2016/03/01 18:06:46 nanard Exp $ */
 /* vim: tabstop=4 shiftwidth=4 noexpandtab
  * MiniUPnP project
  * (c) 2007-2016 Thomas Bernard
@@ -847,7 +847,7 @@ void processRequest(struct reqelem * req)
 	type = buf[0];
 	p = buf + 1;
 	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-	if(p+l > buf+n) {
+	if(l > (unsigned)(buf+n-p)) {
 		syslog(LOG_WARNING, "bad request (length encoding l=%u n=%u)",
 		       l, (unsigned)n);
 		goto error;
@@ -969,7 +969,7 @@ void processRequest(struct reqelem * req)
 			goto error;
 		}
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
@@ -987,7 +987,7 @@ void processRequest(struct reqelem * req)
 		newserv->usn[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
@@ -1005,7 +1005,7 @@ void processRequest(struct reqelem * req)
 		newserv->server[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
```


### `minissdpd/Changelog.txt`

```diff
@@ -1,4 +1,7 @@
-$Id: Changelog.txt,v 1.43 2015/08/06 14:05:49 nanard Exp $
+$Id: Changelog.txt,v 1.45 2016/03/01 18:06:46 nanard Exp $
+
+2016/03/01:
+	Fix broken overflow test (p+l > buf+n) thanks to Salva Piero
 
 VERSION 1.5:
 
```


### `minissdpd/testminissdpd.c`

```diff
@@ -1,4 +1,4 @@
-/* $Id: testminissdpd.c,v 1.12 2015/08/06 13:16:59 nanard Exp $ */
+/* $Id: testminissdpd.c,v 1.14 2016/03/01 17:49:51 nanard Exp $ */
 /* Project : miniupnp
  * website : [url removida] or [url removida]
  * Author : Thomas BERNARD
@@ -65,6 +65,7 @@ main(int argc, char * * argv)
 	const char bad_command[] = { 0xff, 0xff };
 	const char overflow[] = { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
 	const char command5[] = { 0x05, 0x00 };
+	const char bad_command4[] = { 0x04, 0x01, 0x60, 0x8f, 0xff, 0xff, 0xff, 0x7f};
 	int s;
 	int i;
 	void * tmp;
@@ -180,6 +181,15 @@ main(int argc, char * * argv)
 	n = read(s, buf, sizeof(buf));
 	printf("Response received %d bytes\n", (int)n);
 	printresponse(buf, n);
+	if(n == 0) {
+		close(s);
+		s = connect_unix_socket(sockpath);
+	}
+
+	n = SENDCOMMAND(bad_command4, sizeof(bad_command4));
+	n = read(s, buf, sizeof(buf));
+	printf("Response received %d bytes\n", (int)n);
+	printresponse(buf, n);
 
 	close(s);
 	return 0;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
