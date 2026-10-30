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

- projeto: radare2
- CVE: CVE-2018-14016
- CWE atribuida pelo BigVul: CWE-125
- commit: `40b021ba29c8f90ccf7c879fde2580bc73a17e8e`
- URL do commit: https://github.com/radare/radare2/commit/40b021ba29c8f90ccf7c879fde2580bc73a17e8e
- arquivo da funcao marcada: `libr/bin/format/mdmp/mdmp.c`

## Mensagem do commit

> Fix #10464 - oobread crash in mdmp

## Resumo da CVE

> The r_bin_mdmp_init_directory_entry function in mdmp.c in radare2 2.7.0 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted Mini Crash Dump file.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -24,7 +24,7 @@
  	/* We could confirm data sizes but a malcious MDMP will always get around
  	** this! But we can ensure that the data is not outside of the file */
  	if (entry->location.rva + entry->location.data_size > obj->b->length) {
-		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
+		eprintf ("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
  		return false;
  	}
  
```

## Corpo completo da funcao antes da correcao

```c
static bool r_bin_mdmp_init_directory_entry(struct r_bin_mdmp_obj *obj, struct minidump_directory *entry) {
	int i;

	struct minidump_handle_operation_list *handle_operation_list;
	struct minidump_memory_list *memory_list;
	struct minidump_memory64_list *memory64_list;
	struct minidump_memory_info_list *memory_info_list;
	struct minidump_module_list *module_list;
	struct minidump_thread_list *thread_list;
	struct minidump_thread_ex_list *thread_ex_list;
	struct minidump_thread_info_list *thread_info_list;
	struct minidump_unloaded_module_list *unloaded_module_list;

	struct avrf_handle_operation *handle_operations;
	struct minidump_memory_descriptor *memories;
	struct minidump_memory_descriptor64 *memories64;
	struct minidump_memory_info *memory_infos;
	struct minidump_module *modules;
	struct minidump_thread *threads;
	struct minidump_thread_ex *ex_threads;
	struct minidump_thread_info *thread_infos;
	struct minidump_unloaded_module *unloaded_modules;

 	/* We could confirm data sizes but a malcious MDMP will always get around
 	** this! But we can ensure that the data is not outside of the file */
 	if (entry->location.rva + entry->location.data_size > obj->b->length) {
		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
 		return false;
 	}
 
	switch (entry->stream_type) {
	case THREAD_LIST_STREAM:
		thread_list = (struct minidump_thread_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_thread.format", "ddddq?? "
			"ThreadId SuspendCount PriorityClass Priority "
			"Teb (mdmp_memory_descriptor)Stack "
			"(mdmp_location_descriptor)ThreadContext", 0);
		sdb_num_set (obj->kv, "mdmp_thread_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_thread_list.format",
			sdb_fmt ("d[%i]? "
				"NumberOfThreads (mdmp_thread)Threads",
				thread_list->number_of_threads),
			0);

		/* TODO: Not yet fully parsed or utilised */
		for (i = 0; i < thread_list->number_of_threads; i++) {
			threads = (struct minidump_thread *)(&(thread_list->threads));
			r_list_append (obj->streams.threads, &(threads[i]));
		}
		break;
	case MODULE_LIST_STREAM:
		module_list = (struct minidump_module_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_module.format", "qddtd???qq "
			"BaseOfImage SizeOfImage CheckSum "
			"TimeDateStamp ModuleNameRVA "
			"(mdmp_vs_fixedfileinfo)VersionInfo "
			"(mdmp_location_descriptor)CvRecord "
			"(mdmp_location_descriptor)MiscRecord "
			"Reserved0 Reserved1", 0);
		sdb_num_set (obj->kv, "mdmp_module_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_module_list.format",
			sdb_fmt ("d[%i]? "
				"NumberOfModule (mdmp_module)Modules",
				module_list->number_of_modules,
				0),
			0);

		for (i = 0; i < module_list->number_of_modules; i++) {
			modules = (struct minidump_module *)(&(module_list->modules));
			r_list_append(obj->streams.modules, &(modules[i]));
		}
		break;
	case MEMORY_LIST_STREAM:
		memory_list = (struct minidump_memory_list *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_memory_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_memory_list.format",
			sdb_fmt ("d[%i]? "
				"NumberOfMemoryRanges "
				"(mdmp_memory_descriptor)MemoryRanges ",
				memory_list->number_of_memory_ranges,
				0),
			0);

		for (i = 0; i < memory_list->number_of_memory_ranges; i++) {
			memories = (struct minidump_memory_descriptor *)(&(memory_list->memory_ranges));
			r_list_append (obj->streams.memories, &(memories[i]));
		}
		break;
	case EXCEPTION_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.exception = (struct minidump_exception_stream *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_exception.format", "[4]E[4]Eqqdd[15]q "
			"(mdmp_exception_code)ExceptionCode "
			"(mdmp_exception_flags)ExceptionFlags "
			"ExceptionRecord ExceptionAddress "
			"NumberParameters __UnusedAlignment "
			"ExceptionInformation", 0);
		sdb_num_set (obj->kv, "mdmp_exception_stream.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_exception_stream.format", "dd?? "
			"ThreadId __Alignment "
			"(mdmp_exception)ExceptionRecord "
			"(mdmp_location_descriptor)ThreadContext", 0);

		break;
	case SYSTEM_INFO_STREAM:
		obj->streams.system_info = (struct minidump_system_info *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_system_info.offset",
			entry->location.rva, 0);
		/* TODO: We need E as a byte! */
		sdb_set (obj->kv, "mdmp_system_info.format", "[2]EwwbBddd[4]Ed[2]Ew[2]q "
			"(mdmp_processor_architecture)ProcessorArchitecture "
			"ProcessorLevel ProcessorRevision NumberOfProcessors "
			"(mdmp_product_type)ProductType "
			"MajorVersion MinorVersion BuildNumber (mdmp_platform_id)PlatformId "
			"CsdVersionRva (mdmp_suite_mask)SuiteMask Reserved2 ProcessorFeatures", 0);

		break;
	case THREAD_EX_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		thread_ex_list = (struct minidump_thread_ex_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_thread_ex.format", "ddddq??? "
			"ThreadId SuspendCount PriorityClass Priority "
			"Teb (mdmp_memory_descriptor)Stack "
			"(mdmp_location_descriptor)ThreadContext "
			"(mdmp_memory_descriptor)BackingStore", 0);
		sdb_num_set (obj->kv, "mdmp_thread_ex_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_thread_ex_list.format",
			sdb_fmt ("d[%i]? NumberOfThreads "
				"(mdmp_thread_ex)Threads",
				thread_ex_list->number_of_threads, 0),
			0);

		for (i = 0; i < thread_ex_list->number_of_threads; i++) {
			ex_threads = (struct minidump_thread_ex *)(&(thread_ex_list->threads));
			r_list_append (obj->streams.ex_threads, &(ex_threads[i]));
		}
		break;
	case MEMORY_64_LIST_STREAM:
		memory64_list = (struct minidump_memory64_list *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_memory64_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_memory64_list.format",
			sdb_fmt ("qq[%i]? NumberOfMemoryRanges "
				"BaseRva "
				"(mdmp_memory_descriptor64)MemoryRanges",
				memory64_list->number_of_memory_ranges),
			0);

		obj->streams.memories64.base_rva = memory64_list->base_rva;
		for (i = 0; i < memory64_list->number_of_memory_ranges; i++) {
			memories64 = (struct minidump_memory_descriptor64 *)(&(memory64_list->memory_ranges));
			r_list_append (obj->streams.memories64.memories, &(memories64[i]));
		}
		break;
	case COMMENT_STREAM_A:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_a = obj->b->buf + entry->location.rva;

		sdb_num_set (obj->kv, "mdmp_comment_stream_a.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_comment_stream_a.format",
			"s CommentA", 0);

		break;
	case COMMENT_STREAM_W:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_w = obj->b->buf + entry->location.rva;

		sdb_num_set (obj->kv, "mdmp_comment_stream_w.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_comment_stream_w.format",
				"s CommentW", 0);

		break;
	case HANDLE_DATA_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.handle_data = (struct minidump_handle_data_stream *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_handle_data_stream.offset",
				entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_handle_data_stream.format", "dddd "
				"SizeOfHeader SizeOfDescriptor "
				"NumberOfDescriptors Reserved", 0);
		break;
	case FUNCTION_TABLE_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.function_table = (struct minidump_function_table_stream *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_function_table_stream.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_function_table_stream.format", "dddddd "
			"SizeOfHeader SizeOfDescriptor SizeOfNativeDescriptor "
			"SizeOfFunctionEntry NumberOfDescriptors SizeOfAlignPad",
			0);
		break;
	case UNLOADED_MODULE_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		unloaded_module_list = (struct minidump_unloaded_module_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_unloaded_module.format", "qddtd "
			"BaseOfImage SizeOfImage CheckSum TimeDateStamp "
			"ModuleNameRva", 0);
		sdb_num_set (obj->kv, "mdmp_unloaded_module_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_unloaded_module_list.format", "ddd "
			"SizeOfHeader SizeOfEntry NumberOfEntries", 0);

		for (i = 0; i < unloaded_module_list->number_of_entries; i++) {
			unloaded_modules = (struct minidump_unloaded_module *)((ut8 *)&unloaded_module_list + sizeof (struct minidump_unloaded_module_list));
			r_list_append (obj->streams.unloaded_modules, &(unloaded_modules[i]));
		}
		break;
	case MISC_INFO_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.misc_info.misc_info_1 = (struct minidump_misc_info *)(obj->b->buf + entry->location.rva);

		/* TODO: Handle different sizes */
		sdb_num_set (obj->kv, "mdmp_misc_info.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_misc_info.format", "d[4]Bdtttddddd "
			"SizeOfInfo (mdmp_misc1_flags)Flags1 ProcessId "
			"ProcessCreateTime ProcessUserTime ProcessKernelTime "
			"ProcessorMaxMhz ProcessorCurrentMhz "
			"ProcessorMhzLimit ProcessorMaxIdleState "
			"ProcessorCurrentIdleState", 0);

		break;
	case MEMORY_INFO_LIST_STREAM:
		memory_info_list = (struct minidump_memory_info_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_memory_info.format",
			"qq[4]Edq[4]E[4]E[4]Ed BaseAddress AllocationBase "
			"(mdmp_page_protect)AllocationProtect __Alignment1 RegionSize "
			"(mdmp_mem_state)State (mdmp_page_protect)Protect "
			"(mdmp_mem_type)Type __Alignment2", 0);
		sdb_num_set (obj->kv, "mdmp_memory_info_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_memory_info_list.format",
			sdb_fmt ("ddq[%i]? SizeOfHeader SizeOfEntry "
				"NumberOfEntries (mdmp_memory_info)MemoryInfo",
				memory_info_list->number_of_entries),
			0);

		for (i = 0; i < memory_info_list->number_of_entries; i++) {
			memory_infos = (struct minidump_memory_info *)((ut8 *)memory_info_list + sizeof (struct minidump_memory_info_list));
			r_list_append (obj->streams.memory_infos, &(memory_infos[i]));
		}
		break;
	case THREAD_INFO_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		thread_info_list = (struct minidump_thread_info_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_thread_info.format", "ddddttttqq "
			"ThreadId DumpFlags DumpError ExitStatus CreateTime "
			"ExitTime KernelTime UserTime StartAddress Affinity",
			0);
		sdb_num_set (obj->kv, "mdmp_thread_info_list.offset",
				entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_thread_info_list.format", "ddd "
			"SizeOfHeader SizeOfEntry NumberOfEntries", 0);

		for (i = 0; i < thread_info_list->number_of_entries; i++) {
			thread_infos = (struct minidump_thread_info *)((ut8 *)thread_info_list + sizeof (struct minidump_thread_info_list));
			r_list_append (obj->streams.thread_infos, &(thread_infos[i]));
		}
		break;
	case HANDLE_OPERATION_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		handle_operation_list = (struct minidump_handle_operation_list *)(obj->b->buf + entry->location.rva);

		sdb_num_set (obj->kv, "mdmp_handle_operation_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_handle_operation_list.format", "dddd "
			"SizeOfHeader SizeOfEntry NumberOfEntries Reserved", 0);

		for (i = 0; i < handle_operation_list->number_of_entries; i++) {
			handle_operations = (struct avrf_handle_operation *)((ut8 *)handle_operation_list + sizeof (struct minidump_handle_operation_list));
			r_list_append (obj->streams.operations, &(handle_operations[i]));
		}

		break;
	case LAST_RESERVED_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		break;
	case UNUSED_STREAM:
	case RESERVED_STREAM_0:
	case RESERVED_STREAM_1:
		/* Silently ignore reserved streams */
		break;
	default:
		eprintf ("[WARN] Invalid or unsupported enumeration encountered %i\n", entry->stream_type);
		return false;
	}
	return true;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `libr/bin/format/mdmp/mdmp.c` **(funcao marcada esta aqui)** | modified | 8 | 7 |


### `libr/bin/format/mdmp/mdmp.c`

```diff
@@ -362,7 +362,7 @@ static bool r_bin_mdmp_init_directory_entry(struct r_bin_mdmp_obj *obj, struct m
 	/* We could confirm data sizes but a malcious MDMP will always get around
 	** this! But we can ensure that the data is not outside of the file */
 	if (entry->location.rva + entry->location.data_size > obj->b->length) {
-		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
+		eprintf ("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
 		return false;
 	}
 
@@ -646,10 +646,7 @@ static bool r_bin_mdmp_init_directory_entry(struct r_bin_mdmp_obj *obj, struct m
 
 static bool r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj) {
 	int i;
-	ut8 *directory_base;
-	struct minidump_directory *entry;
-
-	directory_base = obj->b->buf + obj->hdr->stream_directory_rva;
+	struct minidump_directory entry;
 
 	sdb_num_set (obj->kv, "mdmp_directory.offset",
 			obj->hdr->stream_directory_rva, 0);
@@ -658,9 +655,13 @@ static bool r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj) {
 			"(mdmp_location_descriptor)Location", 0);
 
 	/* Parse each entry in the directory */
+	ut64 rvadir = obj->hdr->stream_directory_rva;
 	for (i = 0; i < (int)obj->hdr->number_of_streams; i++) {
-		entry = (struct minidump_directory *)(directory_base + (i * sizeof (struct minidump_directory)));
-		r_bin_mdmp_init_directory_entry (obj, entry);
+		ut32 delta = i * sizeof (struct minidump_directory);
+		int r = r_buf_read_at (obj->b, rvadir + delta, (ut8*) &entry, sizeof (struct minidump_directory));
+		if (r) {
+			r_bin_mdmp_init_directory_entry (obj, &entry);
+		}
 	}
 
 	return true;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
