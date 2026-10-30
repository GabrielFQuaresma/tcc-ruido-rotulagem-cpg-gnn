# Pacote de anotacao — caso 23

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

# Evidencia do caso 23

## Identificacao

- projeto: yara
- CVE: CVE-2017-9465
- CWE atribuida pelo BigVul: CWE-125
- commit: `992480c30f75943e9cd6245bb2015c7737f9b661`
- URL do commit: https://github.com/VirusTotal/yara/commit/992480c30f75943e9cd6245bb2015c7737f9b661
- arquivo da funcao marcada: `libyara/scan.c`

## Mensagem do commit

> Fix buffer overrun (issue #678). Add assert for detecting this kind of issues earlier.

## Resumo da CVE

> The yr_arena_write_data function in YARA 3.6.1 allows remote attackers to cause a denial of service (buffer over-read and application crash) or obtain sensitive information from process memory via a crafted file that is mishandled in the yr_re_fast_exec function in libyara/re.c and the _yr_scan_match_callback function in libyara/scan.c.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -16,6 +16,9 @@
 
    match_length += callback_args->forward_matches;
  
+  // make sure that match fits into the data.
+  assert(match_offset + match_length <= callback_args->data_size);
+
    if (callback_args->full_word)
    {
      if (flags & RE_FLAGS_WIDE)
```

## Corpo completo da funcao antes da correcao

```c
int _yr_scan_match_callback(
    uint8_t* match_data,
    int32_t match_length,
    int flags,
    void* args)
{
  CALLBACK_ARGS* callback_args = (CALLBACK_ARGS*) args;

  YR_STRING* string = callback_args->string;
  YR_MATCH* new_match;

  int result = ERROR_SUCCESS;
  int tidx = callback_args->context->tidx;

  size_t match_offset = match_data - callback_args->data;

   match_length += callback_args->forward_matches;
 
   if (callback_args->full_word)
   {
     if (flags & RE_FLAGS_WIDE)
    {
      if (match_offset >= 2 &&
          *(match_data - 1) == 0 &&
          isalnum(*(match_data - 2)))
        return ERROR_SUCCESS;

      if (match_offset + match_length + 1 < callback_args->data_size &&
          *(match_data + match_length + 1) == 0 &&
          isalnum(*(match_data + match_length)))
        return ERROR_SUCCESS;
    }
    else
    {
      if (match_offset >= 1 &&
          isalnum(*(match_data - 1)))
        return ERROR_SUCCESS;

      if (match_offset + match_length < callback_args->data_size &&
          isalnum(*(match_data + match_length)))
        return ERROR_SUCCESS;
    }
  }

  if (STRING_IS_CHAIN_PART(string))
  {
    result = _yr_scan_verify_chained_string_match(
        string,
        callback_args->context,
        match_data,
        callback_args->data_base,
        match_offset,
        match_length);
  }
  else
  {
    if (string->matches[tidx].count == 0)
    {

      FAIL_ON_ERROR(yr_arena_write_data(
          callback_args->context->matching_strings_arena,
          &string,
          sizeof(string),
          NULL));
    }

    FAIL_ON_ERROR(yr_arena_allocate_memory(
        callback_args->context->matches_arena,
        sizeof(YR_MATCH),
        (void**) &new_match));

    new_match->data_length = yr_min(match_length, MAX_MATCH_DATA);

    FAIL_ON_ERROR(yr_arena_write_data(
        callback_args->context->matches_arena,
        match_data,
        new_match->data_length,
        (void**) &new_match->data));

    if (result == ERROR_SUCCESS)
    {
      new_match->base = callback_args->data_base;
      new_match->offset = match_offset;
      new_match->match_length = match_length;
      new_match->prev = NULL;
      new_match->next = NULL;

      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          &string->matches[tidx],
          STRING_IS_GREEDY_REGEXP(string)));
    }
  }

  return result;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **2**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `libyara/re.c` | modified | 3 | 2 |
| `libyara/scan.c` **(funcao marcada esta aqui)** | modified | 3 | 0 |


### `libyara/scan.c`

```diff
@@ -443,6 +443,9 @@ int _yr_scan_match_callback(
   // total match length is the sum of backward and forward matches.
   match_length += callback_args->forward_matches;
 
+  // make sure that match fits into the data.
+  assert(match_offset + match_length <= callback_args->data_size);
+
   if (callback_args->full_word)
   {
     if (flags & RE_FLAGS_WIDE)
```


### `libyara/re.c`

```diff
@@ -2320,11 +2320,11 @@ int yr_re_fast_exec(
 
           for (i = repeat_any_args->min + 1; i <= repeat_any_args->max; i++)
           {
-            next_input = input + i * input_incr;
-
             if (bytes_matched + i >= max_bytes_matched)
               break;
 
+            next_input = input + i * input_incr;
+
             if ( *(next_opcode) != RE_OPCODE_LITERAL ||
                 (*(next_opcode) == RE_OPCODE_LITERAL &&
                  *(next_opcode + 1) == *next_input))
@@ -2341,6 +2341,7 @@ int yr_re_fast_exec(
 
           input += input_incr * repeat_any_args->min;
           bytes_matched += repeat_any_args->min;
+          bytes_matched = yr_min(bytes_matched, max_bytes_matched);
           ip = next_opcode;
 
           break;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
