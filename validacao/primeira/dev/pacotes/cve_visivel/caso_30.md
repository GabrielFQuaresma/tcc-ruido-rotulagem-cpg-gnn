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

- projeto: tnef
- CVE: CVE-2017-6307
- CWE atribuida pelo BigVul: CWE-125
- commit: `1a17af1ed0c791aec44dbdc9eab91218cc1e335a`
- URL do commit: https://github.com/verdammelt/tnef/commit/1a17af1ed0c791aec44dbdc9eab91218cc1e335a
- arquivo da funcao marcada: `src/mapi_attr.c`

## Mensagem do commit

> Use asserts on lengths to prevent invalid reads/writes.

## Resumo da CVE

> An issue was discovered in tnef before 1.4.13. Two OOB Writes have been identified in src/mapi_attr.c:mapi_attr_read(). These might lead to invalid read and write operations, controlled by an attacker.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -4,6 +4,7 @@
      uint32 i,j;
      assert(len > 4);
      uint32 num_properties = GETINT32(buf+idx);
+    assert((num_properties+1) != 0);
      MAPI_Attr** attrs = CHECKED_XMALLOC (MAPI_Attr*, (num_properties + 1));
  
      idx += 4;
@@ -42,6 +43,7 @@
  		    /* read the data into a buffer */
  		    a->names[i].data 
  			= CHECKED_XMALLOC(unsigned char, a->names[i].len);
+		    assert((idx+(a->names[i].len*2)) <= len);
  		    for (j = 0; j < (a->names[i].len >> 1); j++)
  			a->names[i].data[j] = (buf+idx)[j*2];
  
@@ -138,8 +140,11 @@
  	    case szMAPI_BINARY:
  		CHECKINT32(idx, len); v->len = GETINT32(buf+idx); idx += 4;
  
+		assert(v->len + idx <= len);
+
  		if (a->type == szMAPI_UNICODE_STRING)
  		{
+		    assert(v->len != 0);
  		    v->data.buf = (unsigned char*)unicode_to_utf8(v->len, buf+idx);
  		}
  		else
```

## Corpo completo da funcao antes da correcao

```c
mapi_attr_read (size_t len, unsigned char *buf)
{
    size_t idx = 0;
     uint32 i,j;
     assert(len > 4);
     uint32 num_properties = GETINT32(buf+idx);
     MAPI_Attr** attrs = CHECKED_XMALLOC (MAPI_Attr*, (num_properties + 1));
 
     idx += 4;

    if (!attrs) return NULL;
    for (i = 0; i < num_properties; i++)
    {
	MAPI_Attr* a = attrs[i] = CHECKED_XCALLOC(MAPI_Attr, 1);
	MAPI_Value* v = NULL;

	CHECKINT16(idx, len); a->type = GETINT16(buf+idx); idx += 2;
	CHECKINT16(idx, len); a->name = GETINT16(buf+idx); idx += 2;

	/* handle special case of GUID prefixed properties */
	if (a->name & GUID_EXISTS_FLAG)
	{
	    /* copy GUID */
	    a->guid = CHECKED_XMALLOC(GUID, 1);
	    copy_guid_from_buf(a->guid, buf+idx, len);
	    idx += sizeof (GUID);

	    CHECKINT32(idx, len); a->num_names = GETINT32(buf+idx); idx += 4;
	    if (a->num_names > 0)
	    {
		/* FIXME: do something useful here! */
		size_t i;

		a->names = CHECKED_XCALLOC(VarLenData, a->num_names);

		for (i = 0; i < a->num_names; i++)
		{
		    size_t j;

		    CHECKINT32(idx, len); a->names[i].len = GETINT32(buf+idx); idx += 4;

 		    /* read the data into a buffer */
 		    a->names[i].data 
 			= CHECKED_XMALLOC(unsigned char, a->names[i].len);
 		    for (j = 0; j < (a->names[i].len >> 1); j++)
 			a->names[i].data[j] = (buf+idx)[j*2];
 
		    /* But what are we going to do with it? */
		    
		    idx += pad_to_4byte(a->names[i].len);
		}
	    }
	    else
	    {
		/* get the 'real' name */
		CHECKINT32(idx, len); a->name = GETINT32(buf+idx); idx+= 4;
	    }
	}

	/* 
	 * Multi-value types and string/object/binary types have
	 * multiple values 
	 */
	if (a->type & MULTI_VALUE_FLAG ||
	    a->type == szMAPI_STRING ||
	    a->type == szMAPI_UNICODE_STRING ||
	    a->type == szMAPI_OBJECT ||
	    a->type == szMAPI_BINARY)
	{
	    CHECKINT32(idx, len); a->num_values = GETINT32(buf+idx);
	    idx += 4;
	}
        else
        {
	    a->num_values = 1;
        }

	/* Amend the type in case of multi-value type */
	if (a->type & MULTI_VALUE_FLAG)
	{
	    a->type -= MULTI_VALUE_FLAG;
	}


	v = alloc_mapi_values (a);

	for (j = 0; j < a->num_values; j++) 
	{
	    switch (a->type)
	    {
	    case szMAPI_SHORT:	/* 2 bytes */
		v->len = 2;
		CHECKINT16(idx, len); v->data.bytes2 = GETINT16(buf+idx);
		idx += 4;	/* assume padding of 2, advance by 4! */
		break;

	    case szMAPI_INT:	/* 4 bytes */
		v->len = 4;
		CHECKINT32(idx, len); v->data.bytes4 = GETINT32(buf+idx);
		idx += 4;
		v++;
		break;

	    case szMAPI_FLOAT:	/* 4 bytes */
	    case szMAPI_BOOLEAN: /* this should be 2 bytes + 2 padding */
		v->len = 4;
		CHECKINT32(idx, len); v->data.bytes4 = GETINT32(buf+idx);
		idx += v->len;
		break;

	    case szMAPI_SYSTIME: /* 8 bytes */
		v->len = 8;
		CHECKINT32(idx, len); v->data.bytes8[0] = GETINT32(buf+idx);
		CHECKINT32(idx+4, len); v->data.bytes8[1] = GETINT32(buf+idx+4);
		idx += 8;
		v++;
		break;

	    case szMAPI_DOUBLE:	/* 8 bytes */
	    case szMAPI_APPTIME:
	    case szMAPI_CURRENCY:
	    case szMAPI_INT8BYTE:
		v->len = 8;
		CHECKINT32(idx, len); v->data.bytes8[0] = GETINT32(buf+idx);
		CHECKINT32(idx+4, len); v->data.bytes8[1] = GETINT32(buf+idx+4);
		idx += v->len;
		break;

	    case szMAPI_CLSID:
		v->len = sizeof (GUID);
		copy_guid_from_buf(&v->data.guid, buf+idx, len);
		idx += v->len;
		break;

	    case szMAPI_STRING:
	    case szMAPI_UNICODE_STRING:
	    case szMAPI_OBJECT:
 	    case szMAPI_BINARY:
 		CHECKINT32(idx, len); v->len = GETINT32(buf+idx); idx += 4;
 
 		if (a->type == szMAPI_UNICODE_STRING)
 		{
 		    v->data.buf = (unsigned char*)unicode_to_utf8(v->len, buf+idx);
 		}
 		else
		{
		    v->data.buf = CHECKED_XMALLOC(unsigned char, v->len);
		    memmove (v->data.buf, buf+idx, v->len);
		}

		idx += pad_to_4byte(v->len);
		v++;
		break;

	    case szMAPI_NULL:	/* illegal in input tnef streams */
	    case szMAPI_ERROR:
	    case szMAPI_UNSPECIFIED:
		fprintf (stderr,
			 "Invalid attribute, input file may be corrupted\n");
		if (!ENCODE_SKIP) exit (1);

		return NULL;

	    default:		/* should never get here */
		fprintf (stderr,
			 "Undefined attribute, input file may be corrupted\n");
		if (!ENCODE_SKIP) exit (1);

		return NULL;

	    }
	    if (DEBUG_ON) mapi_attr_dump (attrs[i]);
	}
    }
    attrs[i] = NULL;

    return attrs;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/mapi_attr.c` **(funcao marcada esta aqui)** | modified | 5 | 0 |


### `src/mapi_attr.c`

```diff
@@ -174,6 +174,7 @@ mapi_attr_read (size_t len, unsigned char *buf)
     uint32 i,j;
     assert(len > 4);
     uint32 num_properties = GETINT32(buf+idx);
+    assert((num_properties+1) != 0);
     MAPI_Attr** attrs = CHECKED_XMALLOC (MAPI_Attr*, (num_properties + 1));
 
     idx += 4;
@@ -212,6 +213,7 @@ mapi_attr_read (size_t len, unsigned char *buf)
 		    /* read the data into a buffer */
 		    a->names[i].data 
 			= CHECKED_XMALLOC(unsigned char, a->names[i].len);
+		    assert((idx+(a->names[i].len*2)) <= len);
 		    for (j = 0; j < (a->names[i].len >> 1); j++)
 			a->names[i].data[j] = (buf+idx)[j*2];
 
@@ -308,8 +310,11 @@ mapi_attr_read (size_t len, unsigned char *buf)
 	    case szMAPI_BINARY:
 		CHECKINT32(idx, len); v->len = GETINT32(buf+idx); idx += 4;
 
+		assert(v->len + idx <= len);
+
 		if (a->type == szMAPI_UNICODE_STRING)
 		{
+		    assert(v->len != 0);
 		    v->data.buf = (unsigned char*)unicode_to_utf8(v->len, buf+idx);
 		}
 		else
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
