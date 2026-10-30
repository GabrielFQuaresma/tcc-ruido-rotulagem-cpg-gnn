# Pacote de anotacao — caso 05

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

# Evidencia do caso 05

## Identificacao

- projeto: krb5
- CVE: CVE-2015-8631
- CWE atribuida pelo BigVul: CWE-119
- commit: `83ed75feba32e46f736fcce0d96a0445f29b96c2`
- URL do commit: https://github.com/krb5/krb5/commit/83ed75feba32e46f736fcce0d96a0445f29b96c2
- arquivo da funcao marcada: `src/kadmin/server/server_stubs.c`

## Mensagem do commit

> Fix leaks in kadmin server stubs [CVE-2015-8631]
> 
> In each kadmind server stub, initialize the client_name and
> server_name variables, and release them in the cleanup handler.  Many
> of the stubs will otherwise leak the client and server name if
> krb5_unparse_name() fails.  Also make sure to free the prime_arg
> variables in rename_principal_2_svc(), or we can leak the first one if
> unparsing the second one fails.  Discovered by Simo Sorce.
> 
> CVE-2015-8631:
> 
> In all versions of MIT krb5, an authenticated attacker can cause
> kadmind to leak memory by supplying a null principal name in a request
> which uses one.  Repeating these requests will eventually cause
> kadmind to exhaust all available memory.
> 
>     CVSSv2 Vector: AV:N/AC:L/Au:S/C:N/I:N/A:C/E:POC/RL:OF/RC:C
> 
> ticket: 8343 (new)
> target_version: 1.14-next
> target_version: 1.13-next
> tags: pullup

## Resumo da CVE

> Multiple memory leaks in kadmin/server/server_stubs.c in kadmind in MIT Kerberos 5 (aka krb5) before 1.13.4 and 1.14.x before 1.14.1 allow remote authenticated users to cause a denial of service (memory consumption) via a request specifying a NULL principal name.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -2,8 +2,8 @@
  {
      static generic_ret              ret;
      char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
      OM_uint32                       minor_stat;
      kadm5_server_handle_t           handle;
      const char                      *errmsg = NULL;
@@ -44,9 +44,9 @@
          if (errmsg != NULL)
              krb5_free_error_message(handle->context, errmsg);
      }
+exit_func:
      gss_release_buffer(&minor_stat, &client_name);
      gss_release_buffer(&minor_stat, &service_name);
-exit_func:
      free_server_handle(handle);
      return &ret;
  }
```

## Corpo completo da funcao antes da correcao

```c
create_policy_2_svc(cpol_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
    gss_buffer_desc                 client_name,
        service_name;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
        goto exit_func;

    if ((ret.code = check_handle((void *)handle)))
        goto exit_func;

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
        ret.code = KADM5_FAILURE;
        goto exit_func;
    }
    prime_arg = arg->rec.policy;

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
                                                       rqst2name(rqstp),
                                                       ACL_ADD, NULL, NULL)) {
        ret.code = KADM5_AUTH_ADD;
        log_unauth("kadm5_create_policy", prime_arg,
                   &client_name, &service_name, rqstp);

    } else {
        ret.code = kadm5_create_policy((void *)handle, &arg->rec,
                                       arg->mask);
        if( ret.code != 0 )
            errmsg = krb5_get_error_message(handle->context, ret.code);

        log_done("kadm5_create_policy",
                 ((prime_arg == NULL) ? "(null)" : prime_arg), errmsg,
                 &client_name, &service_name, rqstp);

         if (errmsg != NULL)
             krb5_free_error_message(handle->context, errmsg);
     }
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
exit_func:
     free_server_handle(handle);
     return &ret;
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/kadmin/server/server_stubs.c` **(funcao marcada esta aqui)** | modified | 77 | 74 |


### `src/kadmin/server/server_stubs.c`

```diff
@@ -334,7 +334,8 @@ create_principal_2_svc(cprinc_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret          ret;
     char                        *prime_arg;
-    gss_buffer_desc             client_name, service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
     restriction_t               *rp;
@@ -382,10 +383,10 @@ create_principal_2_svc(cprinc_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
-    gss_release_buffer(&minor_stat, &client_name);
-    gss_release_buffer(&minor_stat, &service_name);
 
 exit_func:
+    gss_release_buffer(&minor_stat, &client_name);
+    gss_release_buffer(&minor_stat, &service_name);
     free_server_handle(handle);
     return &ret;
 }
@@ -395,7 +396,8 @@ create_principal3_2_svc(cprinc3_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret          ret;
     char                        *prime_arg;
-    gss_buffer_desc             client_name, service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
     restriction_t               *rp;
@@ -444,10 +446,10 @@ create_principal3_2_svc(cprinc3_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
-    gss_release_buffer(&minor_stat, &client_name);
-    gss_release_buffer(&minor_stat, &service_name);
 
 exit_func:
+    gss_release_buffer(&minor_stat, &client_name);
+    gss_release_buffer(&minor_stat, &service_name);
     free_server_handle(handle);
     return &ret;
 }
@@ -457,8 +459,8 @@ delete_principal_2_svc(dprinc_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -501,10 +503,10 @@ delete_principal_2_svc(dprinc_arg *arg, struct svc_req *rqstp)
 
     }
     free(prime_arg);
-    gss_release_buffer(&minor_stat, &client_name);
-    gss_release_buffer(&minor_stat, &service_name);
 
 exit_func:
+    gss_release_buffer(&minor_stat, &client_name);
+    gss_release_buffer(&minor_stat, &service_name);
     free_server_handle(handle);
     return &ret;
 }
@@ -514,8 +516,8 @@ modify_principal_2_svc(mprinc_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     restriction_t                   *rp;
@@ -559,9 +561,9 @@ modify_principal_2_svc(mprinc_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -570,10 +572,9 @@ generic_ret *
 rename_principal_2_svc(rprinc_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret          ret;
-    char                        *prime_arg1,
-        *prime_arg2;
-    gss_buffer_desc             client_name,
-        service_name;
+    char                        *prime_arg1 = NULL, *prime_arg2 = NULL;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
     restriction_t               *rp;
@@ -655,11 +656,11 @@ rename_principal_2_svc(rprinc_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
 
     }
+exit_func:
     free(prime_arg1);
     free(prime_arg2);
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -669,8 +670,8 @@ get_principal_2_svc(gprinc_arg *arg, struct svc_req *rqstp)
 {
     static gprinc_ret               ret;
     char                            *prime_arg, *funcname;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -719,9 +720,9 @@ get_principal_2_svc(gprinc_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -731,8 +732,8 @@ get_princs_2_svc(gprincs_arg *arg, struct svc_req *rqstp)
 {
     static gprincs_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -777,9 +778,9 @@ get_princs_2_svc(gprincs_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
 
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -789,8 +790,8 @@ chpass_principal_2_svc(chpass_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -840,9 +841,9 @@ chpass_principal_2_svc(chpass_arg *arg, struct svc_req *rqstp)
     }
 
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -852,8 +853,8 @@ chpass_principal3_2_svc(chpass3_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -909,9 +910,9 @@ chpass_principal3_2_svc(chpass3_arg *arg, struct svc_req *rqstp)
     }
 
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -921,8 +922,8 @@ setv4key_principal_2_svc(setv4key_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -969,9 +970,9 @@ setv4key_principal_2_svc(setv4key_arg *arg, struct svc_req *rqstp)
     }
 
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -981,8 +982,8 @@ setkey_principal_2_svc(setkey_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1029,9 +1030,9 @@ setkey_principal_2_svc(setkey_arg *arg, struct svc_req *rqstp)
     }
 
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1041,8 +1042,8 @@ setkey_principal3_2_svc(setkey3_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1092,9 +1093,9 @@ setkey_principal3_2_svc(setkey3_arg *arg, struct svc_req *rqstp)
     }
 
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1106,8 +1107,8 @@ chrand_principal_2_svc(chrand_arg *arg, struct svc_req *rqstp)
     krb5_keyblock               *k;
     int                         nkeys;
     char                        *prime_arg, *funcname;
-    gss_buffer_desc             client_name,
-        service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
     const char                  *errmsg = NULL;
@@ -1164,9 +1165,9 @@ chrand_principal_2_svc(chrand_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1178,8 +1179,8 @@ chrand_principal3_2_svc(chrand3_arg *arg, struct svc_req *rqstp)
     krb5_keyblock               *k;
     int                         nkeys;
     char                        *prime_arg, *funcname;
-    gss_buffer_desc             client_name,
-        service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
     const char                  *errmsg = NULL;
@@ -1241,9 +1242,9 @@ chrand_principal3_2_svc(chrand3_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1253,8 +1254,8 @@ create_policy_2_svc(cpol_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1295,9 +1296,9 @@ create_policy_2_svc(cpol_arg *arg, struct svc_req *rqstp)
         if (errmsg != NULL)
             krb5_free_error_message(handle->context, errmsg);
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1307,8 +1308,8 @@ delete_policy_2_svc(dpol_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1347,9 +1348,9 @@ delete_policy_2_svc(dpol_arg *arg, struct svc_req *rqstp)
         if (errmsg != NULL)
             krb5_free_error_message(handle->context, errmsg);
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1359,8 +1360,8 @@ modify_policy_2_svc(mpol_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1400,9 +1401,9 @@ modify_policy_2_svc(mpol_arg *arg, struct svc_req *rqstp)
         if (errmsg != NULL)
             krb5_free_error_message(handle->context, errmsg);
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1413,8 +1414,8 @@ get_policy_2_svc(gpol_arg *arg, struct svc_req *rqstp)
     static gpol_ret             ret;
     kadm5_ret_t         ret2;
     char                        *prime_arg, *funcname;
-    gss_buffer_desc             client_name,
-        service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_principal_ent_rec     caller_ent;
     kadm5_server_handle_t       handle;
@@ -1475,9 +1476,9 @@ get_policy_2_svc(gpol_arg *arg, struct svc_req *rqstp)
         log_unauth(funcname, prime_arg,
                    &client_name, &service_name, rqstp);
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 
@@ -1488,8 +1489,8 @@ get_pols_2_svc(gpols_arg *arg, struct svc_req *rqstp)
 {
     static gpols_ret                ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1531,17 +1532,18 @@ get_pols_2_svc(gpols_arg *arg, struct svc_req *rqstp)
         if (errmsg != NULL)
             krb5_free_error_message(handle->context, errmsg);
     }
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
 
 getprivs_ret * get_privs_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
 {
     static getprivs_ret            ret;
-    gss_buffer_desc                client_name, service_name;
+    gss_buffer_desc                client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                      minor_stat;
     kadm5_server_handle_t          handle;
     const char                     *errmsg = NULL;
@@ -1571,9 +1573,9 @@ getprivs_ret * get_privs_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
     if (errmsg != NULL)
         krb5_free_error_message(handle->context, errmsg);
 
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1583,7 +1585,8 @@ purgekeys_2_svc(purgekeys_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret          ret;
     char                        *prime_arg, *funcname;
-    gss_buffer_desc             client_name, service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                   minor_stat;
     kadm5_server_handle_t       handle;
 
@@ -1629,9 +1632,9 @@ purgekeys_2_svc(purgekeys_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1641,8 +1644,8 @@ get_strings_2_svc(gstrings_arg *arg, struct svc_req *rqstp)
 {
     static gstrings_ret             ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1688,9 +1691,9 @@ get_strings_2_svc(gstrings_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
@@ -1700,8 +1703,8 @@ set_string_2_svc(sstring_arg *arg, struct svc_req *rqstp)
 {
     static generic_ret              ret;
     char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
     OM_uint32                       minor_stat;
     kadm5_server_handle_t           handle;
     const char                      *errmsg = NULL;
@@ -1744,18 +1747,18 @@ set_string_2_svc(sstring_arg *arg, struct svc_req *rqstp)
             krb5_free_error_message(handle->context, errmsg);
     }
     free(prime_arg);
+exit_func:
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
-exit_func:
     free_server_handle(handle);
     return &ret;
 }
 
 generic_ret *init_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
 {
     static generic_ret         ret;
-    gss_buffer_desc            client_name,
-        service_name;
+    gss_buffer_desc            client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc            service_name = GSS_C_EMPTY_BUFFER;
     kadm5_server_handle_t      handle;
     OM_uint32                  minor_stat;
     const char                 *errmsg = NULL;
@@ -1797,10 +1800,10 @@ generic_ret *init_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
                      rqstp->rq_cred.oa_flavor);
     if (errmsg != NULL)
         krb5_free_error_message(NULL, errmsg);
-    gss_release_buffer(&minor_stat, &client_name);
-    gss_release_buffer(&minor_stat, &service_name);
 
 exit_func:
+    gss_release_buffer(&minor_stat, &client_name);
+    gss_release_buffer(&minor_stat, &service_name);
     return(&ret);
 }
 
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
