# Pacote de anotacao — caso 20

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

# Evidencia do caso 20

## Identificacao

- projeto: ghostscript
- CVE: CVE-2017-17858
- CWE atribuida pelo BigVul: CWE-119
- commit: `55c3f68d638ac1263a386e0aaa004bb6e8bde731`
- URL do commit: http://git.ghostscript.com/?p=mupdf.git;a=commit;h=55c3f68d638ac1263a386e0aaa004bb6e8bde731
- arquivo da funcao marcada: `_ausente_`

## Mensagem do commit

_Nao disponivel neste registro._

## Resumo da CVE

> Heap-based buffer overflow in the ensure_solid_xref function in pdf/pdf-xref.c in Artifex MuPDF 1.12.0 allows a remote attacker to potentially execute arbitrary code via a crafted PDF file, because xref subsection object numbers are unrestricted.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -4,8 +4,8 @@
         pdf_xref_entry *table;
         int i, n;
  
-       if (i0 < 0 || i1 < 0 || i0 > INT_MAX - i1)
-               fz_throw(ctx, FZ_ERROR_GENERIC, "negative xref stream entry index");
+       if (i0 < 0 || i0 > PDF_MAX_OBJECT_NUMBER || i1 < 0 || i1 > PDF_MAX_OBJECT_NUMBER || i0 + i1 - 1 > PDF_MAX_OBJECT_NUMBER)
+               fz_throw(ctx, FZ_ERROR_GENERIC, "xref subsection object numbers are out of range");
  
         table = pdf_xref_find_subsection(ctx, doc, i0, i1);
         for (i = i0; i < i0 + i1; i++)
```

## Corpo completo da funcao antes da correcao

```c
pdf_read_new_xref_section(fz_context *ctx, pdf_document *doc, fz_stream *stm, int64_t i0, int i1, int w0, int w1, int w2)
{
	pdf_xref_entry *table;
        pdf_xref_entry *table;
        int i, n;
 
       if (i0 < 0 || i1 < 0 || i0 > INT_MAX - i1)
               fz_throw(ctx, FZ_ERROR_GENERIC, "negative xref stream entry index");
 
        table = pdf_xref_find_subsection(ctx, doc, i0, i1);
        for (i = i0; i < i0 + i1; i++)
	for (i = i0; i < i0 + i1; i++)
	{
		pdf_xref_entry *entry = &table[i-i0];
		int a = 0;
		int64_t b = 0;
		int c = 0;

		if (fz_is_eof(ctx, stm))
			fz_throw(ctx, FZ_ERROR_GENERIC, "truncated xref stream");

		for (n = 0; n < w0; n++)
			a = (a << 8) + fz_read_byte(ctx, stm);
		for (n = 0; n < w1; n++)
			b = (b << 8) + fz_read_byte(ctx, stm);
		for (n = 0; n < w2; n++)
			c = (c << 8) + fz_read_byte(ctx, stm);

		if (!entry->type)
		{
			int t = w0 ? a : 1;
			entry->type = t == 0 ? 'f' : t == 1 ? 'n' : t == 2 ? 'o' : 0;
			entry->ofs = w1 ? b : 0;
			entry->gen = w2 ? c : 0;
			entry->num = i;
		}
	}

	doc->has_xref_streams = 1;
}

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
