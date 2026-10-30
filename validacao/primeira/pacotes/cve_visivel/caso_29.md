# Pacote de anotacao — caso 29

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

# Evidencia do caso 29

## Identificacao

- projeto: php
- CVE: CVE-2016-4539
- CWE atribuida pelo BigVul: CWE-119
- commit: `dccda88f27a084bcbbb30198ace12b4e7ae961cc`
- URL do commit: https://git.php.net/?p=php-src.git;a=commit;h=dccda88f27a084bcbbb30198ace12b4e7ae961cc
- arquivo da funcao marcada: `_ausente_`

## Mensagem do commit

_Nao disponivel neste registro._

## Resumo da CVE

> The xml_parse_into_struct function in ext/xml/xml.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote attackers to cause a denial of service (buffer under-read and segmentation fault) or possibly have unspecified other impact via crafted XML data in the second argument, leading to a parser level of zero.

## Diff da funcao marcada (func_before vs func_after)

As duas versoes da funcao sao **identicas apos normalizar o espaco**
**em branco** — o diff semantico e vazio.

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  static zval *xml_call_handler(xml_parser *parser, zval *handler, zend_function *function_ptr, int argc, zval **argv)
  {
-       int i;  
+       int i;
         TSRMLS_FETCH();
  
         if (parser && handler && !EG(exception)) {
@@ -13,6 +13,7 @@
                 for (i = 0; i < argc; i++) {
                         args[i] = &argv[i];
                 }
+
                 fci.size = sizeof(fci);
                 fci.function_table = EG(function_table);
                 fci.function_name = handler;
@@ -36,7 +37,7 @@
                                            Z_TYPE_PP(obj) == IS_OBJECT &&
                                            Z_TYPE_PP(method) == IS_STRING) {
                                 php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to call handler %s::%s()", Z_OBJCE_PP(obj)->name, Z_STRVAL_PP(method));
-                       } else 
+                       } else
                                 php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to call handler");
                 }
  
```

## Corpo completo da funcao antes da correcao

```c
 static zval *xml_call_handler(xml_parser *parser, zval *handler, zend_function *function_ptr, int argc, zval **argv)
 {
       int i;  
        TSRMLS_FETCH();
 
        if (parser && handler && !EG(exception)) {
		zval ***args;
		zval *retval;
		int result;
		zend_fcall_info fci;

		args = safe_emalloc(sizeof(zval **), argc, 0);
                for (i = 0; i < argc; i++) {
                        args[i] = &argv[i];
                }
                fci.size = sizeof(fci);
                fci.function_table = EG(function_table);
                fci.function_name = handler;
		fci.symbol_table = NULL;
		fci.object_ptr = parser->object;
		fci.retval_ptr_ptr = &retval;
		fci.param_count = argc;
		fci.params = args;
		fci.no_separation = 0;
		/*fci.function_handler_cache = &function_ptr;*/

		result = zend_call_function(&fci, NULL TSRMLS_CC);
		if (result == FAILURE) {
			zval **method;
			zval **obj;

			if (Z_TYPE_P(handler) == IS_STRING) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to call handler %s()", Z_STRVAL_P(handler));
			} else if (zend_hash_index_find(Z_ARRVAL_P(handler), 0, (void **) &obj) == SUCCESS &&
					   zend_hash_index_find(Z_ARRVAL_P(handler), 1, (void **) &method) == SUCCESS &&
                                           Z_TYPE_PP(obj) == IS_OBJECT &&
                                           Z_TYPE_PP(method) == IS_STRING) {
                                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to call handler %s::%s()", Z_OBJCE_PP(obj)->name, Z_STRVAL_PP(method));
                       } else 
                                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to call handler");
                }
 
		for (i = 0; i < argc; i++) {
			zval_ptr_dtor(args[i]);
		}
		efree(args);

		if (result == FAILURE) {
			return NULL;
		} else {
			return EG(exception) ? NULL : retval;
		}
	} else {
		for (i = 0; i < argc; i++) {
			zval_ptr_dtor(&argv[i]);
		}
		return NULL;
	}
}

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
