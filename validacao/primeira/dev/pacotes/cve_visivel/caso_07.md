# Pacote de anotacao — caso 07

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

# Evidencia do caso 07

## Identificacao

- projeto: Chrome
- CVE: CVE-2018-6063
- CWE atribuida pelo BigVul: CWE-787
- commit: `673ce95d481ea9368c4d4d43ac756ba1d6d9e608`
- URL do commit: https://github.com/chromium/chromium/commit/673ce95d481ea9368c4d4d43ac756ba1d6d9e608
- arquivo da funcao marcada: `components/printing/renderer/print_render_frame_helper.cc`

## Mensagem do commit

> Correct mojo::WrapSharedMemoryHandle usage
> 
> Fixes some incorrect uses of mojo::WrapSharedMemoryHandle which
> were assuming that the call actually has any control over the memory
> protection applied to a handle when mapped.
> 
> Where fixing usage is infeasible for this CL, TODOs are added to
> annotate follow-up work.
> 
> Also updates the API and documentation to (hopefully) improve clarity
> and avoid similar mistakes from being made in the future.
> 
> BUG=792900
> 
> Cq-Include-Trybots: master.tryserver.chromium.android:android_optional_gpu_tests_rel;master.tryserver.chromium.linux:linux_optional_gpu_tests_rel;master.tryserver.chromium.mac:mac_optional_gpu_tests_rel;master.tryserver.chromium.win:win_optional_gpu_tests_rel
> Change-Id: I0578aaa9ca3bfcb01aaf2451315d1ede95458477
> Reviewed-on: https://chromium-review.googlesource.com/818282
> Reviewed-by: Wei Li <weili@chromium.org>
> Reviewed-by: Lei Zhang <thestig@chromium.org>
> Reviewed-by: John Abd-El-Malek <jam@chromium.org>
> Reviewed-by: Daniel Cheng <dcheng@chromium.org>
> Reviewed-by: Sadrul Chowdhury <sadrul@chromium.org>
> Reviewed-by: Yuzhu Shen <yzshen@chromium.org>
> Reviewed-by: Robert Sesek <rsesek@chromium.org>
> Commit-Queue: Ken Rockot <rockot@chromium.org>
> Cr-Commit-Position: refs/heads/master@{#530268}

## Resumo da CVE

> Incorrect use of mojo::WrapSharedMemoryHandle in Mojo in Google Chrome prior to 65.0.3325.146 allowed a remote attacker who had compromised the renderer process to perform an out of bounds memory write via a crafted HTML page.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -5,9 +5,9 @@
    PdfMetafileSkia* metafile = print_preview_context_.metafile();
    PrintHostMsg_DidPreviewDocument_Params preview_params;
  
-  if (!CopyMetafileDataToSharedMem(*metafile,
-                                   &preview_params.metafile_data_handle)) {
-    LOG(ERROR) << "CopyMetafileDataToSharedMem failed";
+  if (!CopyMetafileDataToReadOnlySharedMem(
+          *metafile, &preview_params.metafile_data_handle)) {
+    LOG(ERROR) << "CopyMetafileDataToReadOnlySharedMem failed";
      print_preview_context_.set_error(PREVIEW_ERROR_METAFILE_COPY_FAILED);
      return false;
    }
```

## Corpo completo da funcao antes da correcao

```c
bool PrintRenderFrameHelper::FinalizePrintReadyDocument() {
  DCHECK(!is_print_ready_metafile_sent_);
  print_preview_context_.FinalizePrintReadyDocument();

   PdfMetafileSkia* metafile = print_preview_context_.metafile();
   PrintHostMsg_DidPreviewDocument_Params preview_params;
 
  if (!CopyMetafileDataToSharedMem(*metafile,
                                   &preview_params.metafile_data_handle)) {
    LOG(ERROR) << "CopyMetafileDataToSharedMem failed";
     print_preview_context_.set_error(PREVIEW_ERROR_METAFILE_COPY_FAILED);
     return false;
   }

  preview_params.data_size = metafile->GetDataSize();
  preview_params.document_cookie = print_pages_params_->params.document_cookie;
  preview_params.expected_pages_count =
      print_preview_context_.total_page_count();
  preview_params.modifiable = print_preview_context_.IsModifiable();
  preview_params.preview_request_id =
      print_pages_params_->params.preview_request_id;

  is_print_ready_metafile_sent_ = true;

  Send(new PrintHostMsg_MetafileReadyForPrinting(routing_id(), preview_params));
  return true;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **37**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `components/discardable_memory/client/client_discardable_shared_memory_manager.cc` | modified | 1 | 3 |
| `components/discardable_memory/service/discardable_shared_memory_manager.cc` | modified | 3 | 2 |
| `components/printing/browser/print_composite_client.h` | modified | 2 | 0 |
| `components/printing/renderer/DEPS` | modified | 1 | 0 |
| `components/printing/renderer/print_render_frame_helper.cc` **(funcao marcada esta aqui)** | modified | 21 | 16 |
| `components/printing/renderer/print_render_frame_helper.h` | modified | 3 | 2 |
| `components/printing/renderer/print_render_frame_helper_linux.cc` | modified | 2 | 2 |
| `components/printing/service/pdf_compositor_service_unittest.cc` | modified | 4 | 3 |
| `components/printing/service/public/cpp/pdf_compositor_client.cc` | modified | 3 | 2 |
| `components/printing/service/public/cpp/pdf_compositor_client.h` | modified | 3 | 0 |
| `components/printing/service/public/cpp/pdf_service_mojo_utils.cc` | modified | 5 | 3 |
| `components/viz/client/client_shared_bitmap_manager.cc` | modified | 2 | 1 |
| `content/browser/browser_child_process_host_impl.cc` | modified | 2 | 1 |
| `content/browser/renderer_host/render_process_host_impl.cc` | modified | 2 | 1 |
| `content/renderer/media/mojo_audio_input_ipc.cc` | modified | 3 | 3 |
| `content/renderer/media/mojo_audio_output_ipc.cc` | modified | 4 | 3 |
| `content/renderer/media/video_capture_impl.cc` | modified | 6 | 2 |
| `content/renderer/media/video_capture_impl_unittest.cc` | modified | 15 | 6 |
| `device/gamepad/gamepad_provider.cc` | modified | 4 | 4 |
| `gpu/ipc/client/command_buffer_proxy_impl.cc` | modified | 5 | 3 |
| `media/capture/video/shared_memory_handle_provider.cc` | modified | 14 | 4 |
| `media/capture/video/shared_memory_handle_provider_unittest.cc` | modified | 19 | 11 |
| `media/mojo/clients/mojo_jpeg_decode_accelerator.cc` | modified | 3 | 2 |
| `media/mojo/clients/mojo_video_encode_accelerator.cc` | modified | 12 | 6 |
| `media/mojo/interfaces/jpeg_decode_accelerator_typemap_traits.cc` | modified | 7 | 2 |
| `media/mojo/interfaces/video_frame_struct_traits.cc` | modified | 4 | 1 |
| `media/mojo/services/mojo_audio_input_stream.cc` | modified | 1 | 1 |
| `media/mojo/services/mojo_audio_input_stream_unittest.cc` | modified | 6 | 4 |
| `media/mojo/services/mojo_audio_output_stream.cc` | modified | 2 | 1 |
| `media/mojo/services/mojo_audio_output_stream_unittest.cc` | modified | 6 | 4 |
| `media/mojo/services/mojo_video_encode_accelerator_service.cc` | modified | 1 | 2 |
| `mojo/edk/system/core.cc` | modified | 3 | 2 |
| `mojo/public/c/system/platform_handle.h` | modified | 14 | 15 |
| `mojo/public/cpp/system/platform_handle.cc` | modified | 14 | 9 |
| `mojo/public/cpp/system/platform_handle.h` | modified | 47 | 6 |
| `mojo/public/cpp/system/tests/BUILD.gn` | modified | 1 | 0 |
| `ui/gfx/mojo/buffer_types_struct_traits.cc` | modified | 3 | 2 |


### `components/printing/renderer/print_render_frame_helper.cc`

```diff
@@ -31,6 +31,8 @@
 #include "content/public/renderer/render_frame.h"
 #include "content/public/renderer/render_thread.h"
 #include "content/public/renderer/render_view.h"
+#include "mojo/public/cpp/system/buffer.h"
+#include "mojo/public/cpp/system/platform_handle.h"
 #include "net/base/escape.h"
 #include "printing/features/features.h"
 #include "printing/metafile_skia_wrapper.h"
@@ -1363,9 +1365,9 @@ bool PrintRenderFrameHelper::FinalizePrintReadyDocument() {
   PdfMetafileSkia* metafile = print_preview_context_.metafile();
   PrintHostMsg_DidPreviewDocument_Params preview_params;
 
-  if (!CopyMetafileDataToSharedMem(*metafile,
-                                   &preview_params.metafile_data_handle)) {
-    LOG(ERROR) << "CopyMetafileDataToSharedMem failed";
+  if (!CopyMetafileDataToReadOnlySharedMem(
+          *metafile, &preview_params.metafile_data_handle)) {
+    LOG(ERROR) << "CopyMetafileDataToReadOnlySharedMem failed";
     print_preview_context_.set_error(PREVIEW_ERROR_METAFILE_COPY_FAILED);
     return false;
   }
@@ -1628,8 +1630,8 @@ bool PrintRenderFrameHelper::PrintPagesNative(blink::WebLocalFrame* frame,
 
   metafile.FinishDocument();
 
-  if (!CopyMetafileDataToSharedMem(metafile,
-                                   &page_params.metafile_data_handle)) {
+  if (!CopyMetafileDataToReadOnlySharedMem(metafile,
+                                           &page_params.metafile_data_handle)) {
     return false;
   }
 
@@ -1949,26 +1951,29 @@ void PrintRenderFrameHelper::PrintPageInternal(
 }
 #endif  // !defined(OS_MACOSX)
 
-bool PrintRenderFrameHelper::CopyMetafileDataToSharedMem(
+bool PrintRenderFrameHelper::CopyMetafileDataToReadOnlySharedMem(
     const PdfMetafileSkia& metafile,
     base::SharedMemoryHandle* shared_mem_handle) {
   uint32_t buf_size = metafile.GetDataSize();
   if (buf_size == 0)
     return false;
 
-  std::unique_ptr<base::SharedMemory> shared_buf(
-      content::RenderThread::Get()->HostAllocateSharedMemoryBuffer(buf_size));
-  if (!shared_buf)
+  mojo::ScopedSharedBufferHandle buffer =
+      mojo::SharedBufferHandle::Create(buf_size);
+  if (!buffer.is_valid())
     return false;
 
-  if (!shared_buf->Map(buf_size))
+  mojo::ScopedSharedBufferMapping mapping = buffer->Map(buf_size);
+  if (!mapping)
     return false;
 
-  if (!metafile.GetData(shared_buf->memory(), buf_size))
+  if (!metafile.GetData(mapping.get(), buf_size))
     return false;
 
-  *shared_mem_handle =
-      base::SharedMemory::DuplicateHandle(shared_buf->handle());
+  MojoResult result = mojo::UnwrapSharedMemoryHandle(
+      buffer->Clone(mojo::SharedBufferHandle::AccessMode::READ_ONLY),
+      shared_mem_handle, nullptr, nullptr);
+  DCHECK_EQ(MOJO_RESULT_OK, result);
   return true;
 }
 
@@ -2092,9 +2097,9 @@ bool PrintRenderFrameHelper::PreviewPageRendered(int page_number,
   }
 
   PrintHostMsg_DidPreviewPage_Params preview_page_params;
-  if (!CopyMetafileDataToSharedMem(*metafile,
-                                   &preview_page_params.metafile_data_handle)) {
-    LOG(ERROR) << "CopyMetafileDataToSharedMem failed";
+  if (!CopyMetafileDataToReadOnlySharedMem(
+          *metafile, &preview_page_params.metafile_data_handle)) {
+    LOG(ERROR) << "CopyMetafileDataToReadOnlySharedMem failed";
     print_preview_context_.set_error(PREVIEW_ERROR_METAFILE_COPY_FAILED);
     return false;
   }
```


### `components/discardable_memory/client/client_discardable_shared_memory_manager.cc`

```diff
@@ -391,12 +391,10 @@ void ClientDiscardableSharedMemoryManager::AllocateCompletedOnIO(
     base::SharedMemoryHandle* handle,
     base::ScopedClosureRunner closure_runner,
     mojo::ScopedSharedBufferHandle mojo_handle) {
-  size_t memory_size = 0;
-  bool read_only = false;
   if (!mojo_handle.is_valid())
     return;
   auto result = mojo::UnwrapSharedMemoryHandle(std::move(mojo_handle), handle,
-                                               &memory_size, &read_only);
+                                               nullptr, nullptr);
   DCHECK_EQ(result, MOJO_RESULT_OK);
 }
 
```


### `components/discardable_memory/service/discardable_shared_memory_manager.cc`

```diff
@@ -74,8 +74,9 @@ class MojoDiscardableSharedMemoryManagerImpl
     if (manager_) {
       manager_->AllocateLockedDiscardableSharedMemoryForClient(client_id_, size,
                                                                id, &handle);
-      memory =
-          mojo::WrapSharedMemoryHandle(handle, size, false /* read_only */);
+      memory = mojo::WrapSharedMemoryHandle(
+          handle, size,
+          mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
     }
     std::move(callback).Run(std::move(memory));
   }
```


### `components/printing/browser/print_composite_client.h`

```diff
@@ -18,6 +18,8 @@ class PrintCompositeClient
   explicit PrintCompositeClient(content::WebContents* web_contents);
   ~PrintCompositeClient() override;
 
+  // NOTE: |handle| must be a READ-ONLY base::SharedMemoryHandle, i.e. one
+  // acquired by base::SharedMemory::GetReadOnlyHandle().
   void DoComposite(base::SharedMemoryHandle handle,
                    uint32_t data_size,
                    mojom::PdfCompositor::CompositePdfCallback callback);
```


### `components/printing/renderer/DEPS`

```diff
@@ -1,6 +1,7 @@
 include_rules = [
   "+components/grit/components_resources.h",
   "+content/public/renderer",
+  "+mojo/public",
   "+net/base",
   "+services/service_manager/public/cpp",
   "+third_party/skia",
```


### `components/printing/renderer/print_render_frame_helper.h`

```diff
@@ -307,8 +307,9 @@ class PrintRenderFrameHelper
 
   // Helper methods -----------------------------------------------------------
 
-  bool CopyMetafileDataToSharedMem(const PdfMetafileSkia& metafile,
-                                   base::SharedMemoryHandle* shared_mem_handle);
+  bool CopyMetafileDataToReadOnlySharedMem(
+      const PdfMetafileSkia& metafile,
+      base::SharedMemoryHandle* read_only_shared_mem_handle);
 
   // Helper method to get page layout in points and fit to page if needed.
   static void ComputePageLayoutInPointsForCss(
```


### `components/printing/renderer/print_render_frame_helper_linux.cc`

```diff
@@ -82,8 +82,8 @@ bool PrintRenderFrameHelper::PrintPagesNative(blink::WebLocalFrame* frame,
   return true;
 #else
   PrintHostMsg_DidPrintDocument_Params page_params;
-  if (!CopyMetafileDataToSharedMem(metafile,
-                                   &page_params.metafile_data_handle)) {
+  if (!CopyMetafileDataToReadOnlySharedMem(metafile,
+                                           &page_params.metafile_data_handle)) {
     return false;
   }
 
```


### `components/printing/service/pdf_compositor_service_unittest.cc`

```diff
@@ -144,16 +144,17 @@ class PdfCompositorServiceTest : public service_manager::test::ServiceTest {
     base::SharedMemory shared_memory;
     if (shared_memory.Create(options) && shared_memory.Map(len)) {
       stream.copyTo(shared_memory.memory());
-      return base::SharedMemory::DuplicateHandle(shared_memory.handle());
+      return shared_memory.GetReadOnlyHandle();
     }
     return base::SharedMemoryHandle();
   }
 
   void CallCompositorWithSuccess(mojom::PdfCompositorPtr ptr) {
     auto handle = CreateMSKPInSharedMemory();
     ASSERT_TRUE(handle.IsValid());
-    mojo::ScopedSharedBufferHandle buffer_handle =
-        mojo::WrapSharedMemoryHandle(handle, handle.GetSize(), true);
+    mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
+        handle, handle.GetSize(),
+        mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
     ASSERT_TRUE(buffer_handle->is_valid());
     EXPECT_CALL(*this, CallbackOnSuccess(testing::_)).Times(1);
     ptr->CompositePdf(std::move(buffer_handle),
```


### `components/printing/service/public/cpp/pdf_compositor_client.cc`

```diff
@@ -47,8 +47,9 @@ void PdfCompositorClient::Composite(
   if (!compositor_)
     Connect(connector);
 
-  mojo::ScopedSharedBufferHandle buffer_handle =
-      mojo::WrapSharedMemoryHandle(handle, data_size, true);
+  mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
+      handle, data_size,
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
 
   compositor_->CompositePdf(
       std::move(buffer_handle),
```


### `components/printing/service/public/cpp/pdf_compositor_client.h`

```diff
@@ -18,6 +18,9 @@ class PdfCompositorClient {
   ~PdfCompositorClient();
 
   // Composite the final picture and convert into a PDF file.
+  //
+  // NOTE: |handle| must be a READ-ONLY base::SharedMemoryHandle, i.e. one
+  // acquired by base::SharedMemory::GetReadOnlyHandle().
   void Composite(service_manager::Connector* connector,
                  base::SharedMemoryHandle handle,
                  size_t data_size,
```


### `components/printing/service/public/cpp/pdf_service_mojo_utils.cc`

```diff
@@ -14,16 +14,18 @@ std::unique_ptr<base::SharedMemory> GetShmFromMojoHandle(
     mojo::ScopedSharedBufferHandle handle) {
   base::SharedMemoryHandle memory_handle;
   size_t memory_size = 0;
-  bool read_only_flag = false;
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
 
   const MojoResult result = mojo::UnwrapSharedMemoryHandle(
-      std::move(handle), &memory_handle, &memory_size, &read_only_flag);
+      std::move(handle), &memory_handle, &memory_size, &protection);
   if (result != MOJO_RESULT_OK)
     return nullptr;
   DCHECK_GT(memory_size, 0u);
 
+  const bool read_only =
+      protection == mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly;
   std::unique_ptr<base::SharedMemory> shm =
-      std::make_unique<base::SharedMemory>(memory_handle, read_only_flag);
+      std::make_unique<base::SharedMemory>(memory_handle, read_only);
   if (!shm->Map(memory_size)) {
     DLOG(ERROR) << "Map shared memory failed.";
     return nullptr;
```


### `components/viz/client/client_shared_bitmap_manager.cc`

```diff
@@ -170,7 +170,8 @@ uint32_t ClientSharedBitmapManager::NotifyAllocatedSharedBitmap(
   }
 
   mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
-      handle_to_send, memory->mapped_size(), true /* read_only */);
+      handle_to_send, memory->mapped_size(),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 
   {
     base::AutoLock lock(lock_);
```


### `content/browser/browser_child_process_host_impl.cc`

```diff
@@ -532,7 +532,8 @@ void BrowserChildProcessHostImpl::ShareMetricsAllocatorToProcess() {
         GetHost(),
         mojo::WrapSharedMemoryHandle(
             metrics_allocator_->shared_memory()->handle().Duplicate(),
-            metrics_allocator_->shared_memory()->mapped_size(), false));
+            metrics_allocator_->shared_memory()->mapped_size(),
+            mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite));
   } else {
     HistogramController::GetInstance()->SetHistogramMemory<ChildProcessHost>(
         GetHost(), mojo::ScopedSharedBufferHandle());
```


### `content/browser/renderer_host/render_process_host_impl.cc`

```diff
@@ -3626,7 +3626,8 @@ void RenderProcessHostImpl::CreateSharedRendererHistogramAllocator() {
   HistogramController::GetInstance()->SetHistogramMemory<RenderProcessHost>(
       this, mojo::WrapSharedMemoryHandle(
                 metrics_allocator_->shared_memory()->handle().Duplicate(),
-                metrics_allocator_->shared_memory()->mapped_size(), false));
+                metrics_allocator_->shared_memory()->mapped_size(),
+                mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite));
 }
 
 void RenderProcessHostImpl::ProcessDied(bool already_dead,
```


### `content/renderer/media/mojo_audio_input_ipc.cc`

```diff
@@ -85,11 +85,11 @@ void MojoAudioInputIPC::StreamCreated(
   DCHECK_EQ(result, MOJO_RESULT_OK);
 
   base::SharedMemoryHandle memory_handle;
-  bool read_only = true;
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
   result = mojo::UnwrapSharedMemoryHandle(std::move(shared_memory),
-                                          &memory_handle, nullptr, &read_only);
+                                          &memory_handle, nullptr, &protection);
   DCHECK_EQ(result, MOJO_RESULT_OK);
-  DCHECK(read_only);
+  DCHECK_EQ(protection, mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
 
   delegate_->OnStreamCreated(memory_handle, socket_handle, initially_muted);
 }
```


### `content/renderer/media/mojo_audio_output_ipc.cc`

```diff
@@ -205,12 +205,13 @@ void MojoAudioOutputIPC::StreamCreated(
   DCHECK_EQ(result, MOJO_RESULT_OK);
 
   base::SharedMemoryHandle memory_handle;
-  bool read_only = false;
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
   size_t memory_length = 0;
   result = mojo::UnwrapSharedMemoryHandle(
-      std::move(shared_memory), &memory_handle, &memory_length, &read_only);
+      std::move(shared_memory), &memory_handle, &memory_length, &protection);
   DCHECK_EQ(result, MOJO_RESULT_OK);
-  DCHECK(!read_only);
+  DCHECK_EQ(protection,
+            mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 
   delegate_->OnStreamCreated(memory_handle, socket_handle);
 }
```


### `content/renderer/media/video_capture_impl.cc`

```diff
@@ -242,13 +242,17 @@ void VideoCaptureImpl::OnBufferCreated(int32_t buffer_id,
 
   base::SharedMemoryHandle memory_handle;
   size_t memory_size = 0;
-  bool read_only_flag = false;
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
 
   const MojoResult result = mojo::UnwrapSharedMemoryHandle(
-      std::move(handle), &memory_handle, &memory_size, &read_only_flag);
+      std::move(handle), &memory_handle, &memory_size, &protection);
   DCHECK_EQ(MOJO_RESULT_OK, result);
   DCHECK_GT(memory_size, 0u);
 
+  // TODO(https://crbug.com/803136): We should also be able to assert that the
+  // unwrapped handle was shared for read-only mapping. That condition is not
+  // currently guaranteed to be met.
+
   std::unique_ptr<base::SharedMemory> shm(
       new base::SharedMemory(memory_handle, true /* read_only */));
   if (!shm->Map(memory_size)) {
```


### `content/renderer/media/video_capture_impl_unittest.cc`

```diff
@@ -135,11 +135,20 @@ class VideoCaptureImplTest : public ::testing::Test {
     video_capture_impl_->StopCapture(client_id);
   }
 
+  bool CreateAndMapSharedMemory(size_t size, base::SharedMemory* shm) {
+    base::SharedMemoryCreateOptions options;
+    options.size = size;
+    options.share_read_only = true;
+    if (!shm->Create(options))
+      return false;
+    return shm->Map(size);
+  }
+
   void SimulateOnBufferCreated(int buffer_id, const base::SharedMemory& shm) {
-    auto handle = base::SharedMemory::DuplicateHandle(shm.handle());
     video_capture_impl_->OnBufferCreated(
-        buffer_id, mojo::WrapSharedMemoryHandle(handle, shm.mapped_size(),
-                                                true /* read_only */));
+        buffer_id, mojo::WrapSharedMemoryHandle(
+                       shm.GetReadOnlyHandle(), shm.mapped_size(),
+                       mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly));
   }
 
   void SimulateBufferReceived(int buffer_id, const gfx::Size& size) {
@@ -278,7 +287,7 @@ TEST_F(VideoCaptureImplTest, BufferReceived) {
   base::SharedMemory shm;
   const size_t frame_size = media::VideoFrame::AllocationSize(
       media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
-  ASSERT_TRUE(shm.CreateAndMapAnonymous(frame_size));
+  ASSERT_TRUE(CreateAndMapSharedMemory(frame_size, &shm));
 
   EXPECT_CALL(*this, OnStateUpdate(VIDEO_CAPTURE_STATE_STARTED));
   EXPECT_CALL(*this, OnStateUpdate(VIDEO_CAPTURE_STATE_STOPPED));
@@ -303,7 +312,7 @@ TEST_F(VideoCaptureImplTest, BufferReceivedAfterStop) {
   base::SharedMemory shm;
   const size_t frame_size = media::VideoFrame::AllocationSize(
       media::PIXEL_FORMAT_I420, params_large_.requested_format.frame_size);
-  ASSERT_TRUE(shm.CreateAndMapAnonymous(frame_size));
+  ASSERT_TRUE(CreateAndMapSharedMemory(frame_size, &shm));
 
   EXPECT_CALL(*this, OnStateUpdate(VIDEO_CAPTURE_STATE_STARTED));
   EXPECT_CALL(*this, OnStateUpdate(VIDEO_CAPTURE_STATE_STOPPED));
@@ -371,7 +380,7 @@ TEST_F(VideoCaptureImplTest, BufferReceivedBeforeOnStarted) {
   base::SharedMemory shm;
   const size_t frame_size = media::VideoFrame::AllocationSize(
       media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
-  ASSERT_TRUE(shm.CreateAndMapAnonymous(frame_size));
+  ASSERT_TRUE(CreateAndMapSharedMemory(frame_size, &shm));
 
   InSequence s;
   EXPECT_CALL(mock_video_capture_host_, DoStart(_, kSessionId, params_small_))
```


### `device/gamepad/gamepad_provider.cc`

```diff
@@ -90,10 +90,10 @@ base::SharedMemoryHandle GamepadProvider::DuplicateSharedMemoryHandle() {
 mojo::ScopedSharedBufferHandle GamepadProvider::GetSharedBufferHandle() {
   // TODO(heke): Use mojo::SharedBuffer rather than base::SharedMemory in
   // GamepadSharedBuffer. See crbug.com/670655 for details
-  base::SharedMemoryHandle handle = base::SharedMemory::DuplicateHandle(
-      gamepad_shared_buffer_->shared_memory()->handle());
-  return mojo::WrapSharedMemoryHandle(handle, sizeof(GamepadHardwareBuffer),
-                                      true /* read_only */);
+  return mojo::WrapSharedMemoryHandle(
+      gamepad_shared_buffer_->shared_memory()->GetReadOnlyHandle(),
+      sizeof(GamepadHardwareBuffer),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
 }
 
 void GamepadProvider::GetCurrentGamepadData(Gamepads* data) {
```


### `gpu/ipc/client/command_buffer_proxy_impl.cc`

```diff
@@ -751,16 +751,18 @@ CommandBufferProxyImpl::AllocateAndMapSharedMemory(size_t size) {
 
   base::SharedMemoryHandle platform_handle;
   size_t shared_memory_size;
-  bool readonly;
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
   MojoResult result = mojo::UnwrapSharedMemoryHandle(
-      std::move(handle), &platform_handle, &shared_memory_size, &readonly);
+      std::move(handle), &platform_handle, &shared_memory_size, &protection);
   if (result != MOJO_RESULT_OK) {
     DLOG(ERROR) << "AllocateAndMapSharedMemory: Unwrap failed";
     return nullptr;
   }
   DCHECK_EQ(shared_memory_size, size);
 
-  auto shm = std::make_unique<base::SharedMemory>(platform_handle, readonly);
+  bool read_only =
+      protection == mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly;
+  auto shm = std::make_unique<base::SharedMemory>(platform_handle, read_only);
   if (!shm->Map(size)) {
     DLOG(ERROR) << "AllocateAndMapSharedMemory: Map failed";
     return nullptr;
```


### `media/capture/video/shared_memory_handle_provider.cc`

```diff
@@ -52,11 +52,13 @@ bool SharedMemoryHandleProvider::InitFromMojoHandle(
   DCHECK(!shared_memory_);
 
   base::SharedMemoryHandle memory_handle;
-  const MojoResult result =
-      mojo::UnwrapSharedMemoryHandle(std::move(buffer_handle), &memory_handle,
-                                     &mapped_size_, &read_only_flag_);
+  mojo::UnwrappedSharedMemoryHandleProtection protection;
+  const MojoResult result = mojo::UnwrapSharedMemoryHandle(
+      std::move(buffer_handle), &memory_handle, &mapped_size_, &protection);
   if (result != MOJO_RESULT_OK)
     return false;
+  read_only_flag_ =
+      protection == mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly;
   shared_memory_.emplace(memory_handle, read_only_flag_);
   return true;
 }
@@ -68,9 +70,17 @@ SharedMemoryHandleProvider::GetHandleForInterProcessTransit(bool read_only) {
     NOTREACHED();
     return mojo::ScopedSharedBufferHandle();
   }
+  // TODO(https://crbug.com/803136): This does not actually obey |read_only| in
+  // any capacity because it uses DuplicateHandle. In order to properly obey
+  // |read_only| (when true), we need to use |SharedMemory::GetReadOnlyHandle()|
+  // but that is not possible. With the base::SharedMemory API and this
+  // SharedMemoryHandleProvider API as they are today, it isn't possible to know
+  // whether |shared_memory_| even supports read-only duplication. Note that
+  // changing |kReadWrite| to |kReadOnly| does NOT affect the ability to map
+  // the handle read-write.
   return mojo::WrapSharedMemoryHandle(
       base::SharedMemory::DuplicateHandle(shared_memory_->handle()),
-      mapped_size_, read_only);
+      mapped_size_, mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 }
 
 base::SharedMemoryHandle
```


### `media/capture/video/shared_memory_handle_provider_unittest.cc`

```diff
@@ -28,18 +28,18 @@ class SharedMemoryHandleProviderTest : public ::testing::Test {
   SharedMemoryHandleProviderTest() = default;
   ~SharedMemoryHandleProviderTest() override = default;
 
-  void UnwrapAndVerifyMojoHandle(mojo::ScopedSharedBufferHandle buffer_handle,
-                                 size_t expected_size,
-                                 bool expected_read_only_flag) {
+  void UnwrapAndVerifyMojoHandle(
+      mojo::ScopedSharedBufferHandle buffer_handle,
+      size_t expected_size,
+      mojo::UnwrappedSharedMemoryHandleProtection expected_protection) {
     base::SharedMemoryHandle memory_handle;
     size_t memory_size = 0;
-    bool read_only_flag = false;
-    const MojoResult result =
-        mojo::UnwrapSharedMemoryHandle(std::move(buffer_handle), &memory_handle,
-                                       &memory_size, &read_only_flag);
+    mojo::UnwrappedSharedMemoryHandleProtection protection;
+    const MojoResult result = mojo::UnwrapSharedMemoryHandle(
+        std::move(buffer_handle), &memory_handle, &memory_size, &protection);
     EXPECT_EQ(MOJO_RESULT_OK, result);
     EXPECT_EQ(expected_size, memory_size);
-    EXPECT_EQ(expected_read_only_flag, read_only_flag);
+    EXPECT_EQ(expected_protection, protection);
   }
 
  protected:
@@ -55,7 +55,13 @@ TEST_F(SharedMemoryHandleProviderTest,
 
   auto mojo_handle =
       handle_provider_.GetHandleForInterProcessTransit(true /* read_only */);
-  UnwrapAndVerifyMojoHandle(std::move(mojo_handle), kMemorySize, true);
+
+  // TODO(https://crbug.com/803136): See comment within
+  // GetHandleForInterProcessTransit() for an explanation of why this
+  // intentionally read-write even though it ought to be read-only.
+  UnwrapAndVerifyMojoHandle(
+      std::move(mojo_handle), kMemorySize,
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 }
 
 TEST_F(SharedMemoryHandleProviderTest,
@@ -64,7 +70,9 @@ TEST_F(SharedMemoryHandleProviderTest,
 
   auto mojo_handle =
       handle_provider_.GetHandleForInterProcessTransit(false /* read_only */);
-  UnwrapAndVerifyMojoHandle(std::move(mojo_handle), kMemorySize, false);
+  UnwrapAndVerifyMojoHandle(
+      std::move(mojo_handle), kMemorySize,
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 }
 
-};  // namespace media
+}  // namespace media
```


### `media/mojo/clients/mojo_jpeg_decode_accelerator.cc`

```diff
@@ -65,8 +65,9 @@ void MojoJpegDecodeAccelerator::Decode(
   size_t output_buffer_size = VideoFrame::AllocationSize(
       video_frame->format(), video_frame->coded_size());
   mojo::ScopedSharedBufferHandle output_frame_handle =
-      mojo::WrapSharedMemoryHandle(output_handle, output_buffer_size,
-                                   false /* read_only */);
+      mojo::WrapSharedMemoryHandle(
+          output_handle, output_buffer_size,
+          mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 
   // base::Unretained is safe because |this| owns |jpeg_decoder_|.
   jpeg_decoder_->Decode(bitstream_buffer, video_frame->coded_size(),
```


### `media/mojo/clients/mojo_video_encode_accelerator.cc`

```diff
@@ -142,9 +142,13 @@ void MojoVideoEncodeAccelerator::Encode(const scoped_refptr<VideoFrame>& frame,
 
   // WrapSharedMemoryHandle() takes ownership of the handle passed to it, but we
   // don't have ownership of frame->shared_memory_handle(), so Duplicate() it.
-  mojo::ScopedSharedBufferHandle handle =
-      mojo::WrapSharedMemoryHandle(frame->shared_memory_handle().Duplicate(),
-                                   allocation_size, true /* read_only */);
+  //
+  // TODO(https://crbug.com/793446): This should be changed to wrap the frame
+  // buffer handle as read-only, but VideoFrame does not seem to guarantee that
+  // its shared_memory_handle() is in fact read-only.
+  mojo::ScopedSharedBufferHandle handle = mojo::WrapSharedMemoryHandle(
+      frame->shared_memory_handle().Duplicate(), allocation_size,
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 
   const size_t y_offset = frame->shared_memory_offset();
   const size_t u_offset = y_offset + frame->data(VideoFrame::kUPlane) -
@@ -174,11 +178,13 @@ void MojoVideoEncodeAccelerator::UseOutputBitstreamBuffer(
            << " buffer.size()= " << buffer.size() << "B";
   DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
 
-  // WrapSharedMemoryHandle() takes ownership of the handle passed to it, but we
-  // don't have ownership of the |buffer|s underlying handle, so Duplicate() it.
   DCHECK(buffer.handle().IsValid());
+
+  // TODO(https://crbug.com/793446): Only wrap read-only handles here and change
+  // the protection status to kReadOnly.
   mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
-      buffer.handle().Duplicate(), buffer.size(), true /* read_only */);
+      buffer.handle().Duplicate(), buffer.size(),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 
   vea_->UseOutputBitstreamBuffer(buffer.id(), std::move(buffer_handle));
 }
```


### `media/mojo/interfaces/jpeg_decode_accelerator_typemap_traits.cc`

```diff
@@ -72,8 +72,13 @@ StructTraits<media::mojom::BitstreamBufferDataView, media::BitstreamBuffer>::
     DLOG(ERROR) << "Failed to duplicate handle of BitstreamBuffer";
     return mojo::ScopedSharedBufferHandle();
   }
-  return mojo::WrapSharedMemoryHandle(input_handle, input.size(),
-                                      true /* read_only */);
+
+  // TODO(https://crbug.com/793446): Update this to |kReadOnly| protection once
+  // BitstreamBuffer can guarantee that its handle() field always corresponds to
+  // a read-only SharedMemoryHandle.
+  return mojo::WrapSharedMemoryHandle(
+      input_handle, input.size(),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 }
 
 // static
```


### `media/mojo/interfaces/video_frame_struct_traits.cc`

```diff
@@ -26,8 +26,11 @@ media::mojom::VideoFrameDataPtr MakeVideoFrameData(
     media::MojoSharedBufferVideoFrame* mojo_frame =
         static_cast<media::MojoSharedBufferVideoFrame*>(input.get());
 
+    // TODO(https://crbug.com/803136): This should duplicate as READ_ONLY, but
+    // can't because there is no guarantee that the input handle is sharable as
+    // read-only.
     mojo::ScopedSharedBufferHandle dup = mojo_frame->Handle().Clone(
-        mojo::SharedBufferHandle::AccessMode::READ_ONLY);
+        mojo::SharedBufferHandle::AccessMode::READ_WRITE);
     DCHECK(dup.is_valid());
 
     return media::mojom::VideoFrameData::NewSharedBufferData(
```


### `media/mojo/services/mojo_audio_input_stream.cc`

```diff
@@ -84,7 +84,7 @@ void MojoAudioInputStream::OnStreamCreated(
 
   mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
       foreign_memory_handle, shared_memory->requested_size(),
-      /*read_only*/ true);
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
   mojo::ScopedHandle socket_handle =
       mojo::WrapPlatformFile(foreign_socket->Release());
 
```


### `media/mojo/services/mojo_audio_input_stream_unittest.cc`

```diff
@@ -109,13 +109,15 @@ class MockClient : public mojom::AudioInputStreamClient {
 
     size_t memory_length;
     base::SharedMemoryHandle shmem_handle;
-    bool read_only;
+    mojo::UnwrappedSharedMemoryHandleProtection protection;
     EXPECT_EQ(
         mojo::UnwrapSharedMemoryHandle(std::move(shared_buffer), &shmem_handle,
-                                       &memory_length, &read_only),
+                                       &memory_length, &protection),
         MOJO_RESULT_OK);
-    EXPECT_TRUE(read_only);
-    buffer_ = std::make_unique<base::SharedMemory>(shmem_handle, read_only);
+    EXPECT_EQ(protection,
+              mojo::UnwrappedSharedMemoryHandleProtection::kReadOnly);
+    buffer_ = std::make_unique<base::SharedMemory>(shmem_handle,
+                                                   true /* read_only */);
 
     GotNotification(initially_muted);
   }
```


### `media/mojo/services/mojo_audio_output_stream.cc`

```diff
@@ -87,7 +87,8 @@ void MojoAudioOutputStream::OnStreamCreated(
   }
 
   mojo::ScopedSharedBufferHandle buffer_handle = mojo::WrapSharedMemoryHandle(
-      foreign_memory_handle, shared_memory->requested_size(), false);
+      foreign_memory_handle, shared_memory->requested_size(),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
   mojo::ScopedHandle socket_handle =
       mojo::WrapPlatformFile(foreign_socket->Release());
 
```


### `media/mojo/services/mojo_audio_output_stream_unittest.cc`

```diff
@@ -107,13 +107,15 @@ class MockClient : public mojom::AudioOutputStreamClient {
 
     size_t memory_length;
     base::SharedMemoryHandle shmem_handle;
-    bool read_only;
+    mojo::UnwrappedSharedMemoryHandleProtection protection;
     EXPECT_EQ(
         mojo::UnwrapSharedMemoryHandle(std::move(shared_buffer), &shmem_handle,
-                                       &memory_length, &read_only),
+                                       &memory_length, &protection),
         MOJO_RESULT_OK);
-    EXPECT_FALSE(read_only);
-    buffer_ = std::make_unique<base::SharedMemory>(shmem_handle, read_only);
+    EXPECT_EQ(protection,
+              mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
+    buffer_ = std::make_unique<base::SharedMemory>(shmem_handle,
+                                                   false /* read_only */);
 
     GotNotification();
   }
```


### `media/mojo/services/mojo_video_encode_accelerator_service.cc`

```diff
@@ -136,9 +136,8 @@ void MojoVideoEncodeAcceleratorService::UseOutputBitstreamBuffer(
 
   base::SharedMemoryHandle handle;
   size_t memory_size = 0;
-  bool read_only = false;
   auto result = mojo::UnwrapSharedMemoryHandle(std::move(buffer), &handle,
-                                               &memory_size, &read_only);
+                                               &memory_size, nullptr);
   if (result != MOJO_RESULT_OK || memory_size == 0u) {
     DLOG(ERROR) << __func__ << " mojo::UnwrapSharedMemoryHandle() failed";
     NotifyError(::media::VideoEncodeAccelerator::kPlatformFailureError);
```


### `mojo/edk/system/core.cc`

```diff
@@ -1052,7 +1052,8 @@ MojoResult Core::WrapPlatformSharedBufferHandle(
 
   base::UnguessableToken token =
       base::UnguessableToken::Deserialize(guid->high, guid->low);
-  bool read_only = flags & MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY;
+  const bool read_only =
+      flags & MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY;
   scoped_refptr<PlatformSharedBuffer> platform_buffer =
       PlatformSharedBuffer::CreateFromPlatformHandle(size, read_only, token,
                                                      std::move(handle));
@@ -1111,7 +1112,7 @@ MojoResult Core::UnwrapPlatformSharedBufferHandle(
   DCHECK(flags);
   *flags = MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE;
   if (platform_shared_buffer->IsReadOnly())
-    *flags |= MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY;
+    *flags |= MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY;
 
   ScopedPlatformHandle handle = platform_shared_buffer->PassPlatformHandle();
   return ScopedPlatformHandleToMojoPlatformHandle(std::move(handle),
```


### `mojo/public/c/system/platform_handle.h`

```diff
@@ -79,9 +79,14 @@ struct MOJO_ALIGNAS(8) MojoSharedBufferGuid {
 // |MojoPlatformSharedBufferHandleFlags|: Flags relevant to wrapped platform
 //     shared buffers.
 //
-//   |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_NONE| - No flags.
-//   |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_READ_ONLY| - Indicates that the wrapped
-//       buffer handle may only be mapped for reading.
+//   |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE| - No flags.
+//   |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY| - Indicates
+//       that the handle being wrapped is mappable only to read-only memory.
+//
+//       IMPORTANT: THIS DOES NOT CONTROL MEMORY PROTECTION ON THE WRAPPED
+//       HANDLE. It merely conveys a |MojoWrapPlatformSharedBufferHandle()|
+//       caller's knowledge about whether or not the handle being wrapped is
+//       already read-only.
 
 typedef uint32_t MojoPlatformSharedBufferHandleFlags;
 
@@ -90,12 +95,12 @@ const MojoPlatformSharedBufferHandleFlags
     MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE = 0;
 
 const MojoPlatformSharedBufferHandleFlags
-    MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY = 1 << 0;
+    MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY = 1 << 0;
 #else
 #define MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE \
   ((MojoPlatformSharedBufferHandleFlags)0)
 
-#define MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY \
+#define MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY \
   ((MojoPlatformSharedBufferHandleFlags)1 << 0)
 #endif
 
@@ -145,14 +150,7 @@ MojoUnwrapPlatformHandle(MojoHandle mojo_handle,
 //     shared buffer object.
 // |num_bytes|: The size of the shared buffer in bytes.
 // |flags|: Flags which influence the treatment of the shared buffer object. See
-//     below.
-//
-// Flags:
-//    |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE| indicates default behavior.
-//        No flags set.
-//    |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY| indicates that the
-//        buffer handled to be wrapped may only be mapped as read-only. This
-//        flag does NOT change the access control of the buffer in any way.
+//     the |MojoPlatformSharedBufferHandleFlags| definition for details.
 //
 // Returns:
 //     |MOJO_RESULT_OK| if the handle was successfully wrapped. In this case
@@ -186,8 +184,9 @@ MOJO_SYSTEM_EXPORT MojoResult MojoWrapPlatformSharedBufferHandle(
 //        shared buffer handle.
 //
 // Flags which may be set in |*flags| upon success:
-//    |MOJO_PLATFORM_SHARED_BUFFER_FLAG_READ_ONLY| is set iff the unwrapped
-//        shared buffer handle may only be mapped as read-only.
+//    |MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY| is set iff
+//        the unwrapped shared buffer handle can only be mapped to a read-only
+//        memory segment.
 MOJO_SYSTEM_EXPORT MojoResult MojoUnwrapPlatformSharedBufferHandle(
     MojoHandle mojo_handle,
     struct MojoPlatformHandle* platform_handle,
```


### `mojo/public/cpp/system/platform_handle.cc`

```diff
@@ -65,7 +65,7 @@ MojoResult UnwrapPlatformFile(ScopedHandle handle, base::PlatformFile* file) {
 ScopedSharedBufferHandle WrapSharedMemoryHandle(
     const base::SharedMemoryHandle& memory_handle,
     size_t size,
-    bool read_only) {
+    UnwrappedSharedMemoryHandleProtection protection) {
   if (!memory_handle.IsValid())
     return ScopedSharedBufferHandle();
   MojoPlatformHandle platform_handle;
@@ -81,8 +81,8 @@ ScopedSharedBufferHandle WrapSharedMemoryHandle(
 
   MojoPlatformSharedBufferHandleFlags flags =
       MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_NONE;
-  if (read_only)
-    flags |= MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY;
+  if (protection == UnwrappedSharedMemoryHandleProtection::kReadOnly)
+    flags |= MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY;
 
   MojoSharedBufferGuid guid;
   guid.high = memory_handle.GetGUID().GetHighForSerialization();
@@ -95,10 +95,11 @@ ScopedSharedBufferHandle WrapSharedMemoryHandle(
   return ScopedSharedBufferHandle(SharedBufferHandle(mojo_handle));
 }
 
-MojoResult UnwrapSharedMemoryHandle(ScopedSharedBufferHandle handle,
-                                    base::SharedMemoryHandle* memory_handle,
-                                    size_t* size,
-                                    bool* read_only) {
+MojoResult UnwrapSharedMemoryHandle(
+    ScopedSharedBufferHandle handle,
+    base::SharedMemoryHandle* memory_handle,
+    size_t* size,
+    UnwrappedSharedMemoryHandleProtection* protection) {
   if (!handle.is_valid())
     return MOJO_RESULT_INVALID_ARGUMENT;
   MojoPlatformHandle platform_handle;
@@ -116,8 +117,12 @@ MojoResult UnwrapSharedMemoryHandle(ScopedSharedBufferHandle handle,
   if (size)
     *size = num_bytes;
 
-  if (read_only)
-    *read_only = flags & MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_READ_ONLY;
+  if (protection) {
+    *protection =
+        flags & MOJO_PLATFORM_SHARED_BUFFER_HANDLE_FLAG_HANDLE_IS_READ_ONLY
+            ? UnwrappedSharedMemoryHandleProtection::kReadOnly
+            : UnwrappedSharedMemoryHandleProtection::kReadWrite;
+  }
 
   base::UnguessableToken guid =
       base::UnguessableToken::Deserialize(mojo_guid.high, mojo_guid.low);
```


### `mojo/public/cpp/system/platform_handle.h`

```diff
@@ -53,6 +53,20 @@ const MojoPlatformHandleType kPlatformSharedBufferHandleType =
     MOJO_PLATFORM_HANDLE_TYPE_WINDOWS_HANDLE;
 #endif  // defined(OS_POSIX)
 
+// Used to specify the protection status of a base::SharedMemoryHandle memory
+// handle wrapped or unwrapped by mojo::WrapSharedMemoryHandle or
+// mojo::UnwrapSharedMemoryHandle below. See those functions for additional
+// details.
+enum class UnwrappedSharedMemoryHandleProtection {
+  // Indicates that the base::SharedMemoryHandle supports being mapped to
+  // writable memory regions.
+  kReadWrite,
+
+  // Indicates that the base::SharedMemoryHandle supports being mapped only to
+  // read-only memory regions.
+  kReadOnly,
+};
+
 // Wraps a PlatformFile as a Mojo handle. Takes ownership of the file object.
 MOJO_CPP_SYSTEM_EXPORT
 ScopedHandle WrapPlatformFile(base::PlatformFile platform_file);
@@ -62,22 +76,49 @@ MOJO_CPP_SYSTEM_EXPORT
 MojoResult UnwrapPlatformFile(ScopedHandle handle, base::PlatformFile* file);
 
 // Wraps a base::SharedMemoryHandle as a Mojo handle. Takes ownership of the
-// SharedMemoryHandle. Note that |read_only| is only an indicator of whether
-// |memory_handle| only supports read-only mapping. It does NOT have any
-// influence on the access control of the shared buffer object.
+// SharedMemoryHandle. |size| indicates the size of the underlying
+// base::SharedMemory object, and |current_protection| indicates whether or
+// not |memory_handle| supports being mapped to writable memory segments.
+//
+// ***** IMPORTANT. PLEASE READ BELOW CAREFULLY. *****
+//
+// THIS CALL DOES NOT IN ANY WAY AFFECT THE MEMORY PROTECTION STATUS OF THE
+// WRAPPED HANDLE.
+//
+// The |current_protection| argument is only an indication of the current memory
+// protection status of |memory_handle| as known by the caller.
+//
+// DO NOT wrap a writable |memory_handle| with |current_protection| set to
+// |UnwrappedSharedMemoryHandleProtection::kReadOnly|, as this will mislead
+// corresponding callers to |UnwrapSharedMemoryHandle()|: the subsequently
+// unwrapped SharedMemoryHandle will appear to be read-only on the surface, but
+// will still be mappable to a writable memory segment.
+//
+// Use base::SharedMemory::GetReadOnlyHandle() to acquire a read-only handle to
+// a shared memory object if you intend to wrap the handle with
+// |UnwrappedSharedMemoryHandleProtection::kReadOnly|.
 MOJO_CPP_SYSTEM_EXPORT
 ScopedSharedBufferHandle WrapSharedMemoryHandle(
     const base::SharedMemoryHandle& memory_handle,
     size_t size,
-    bool read_only);
+    UnwrappedSharedMemoryHandleProtection current_protection);
 
 // Unwraps a base::SharedMemoryHandle from a Mojo handle. The caller assumes
-// responsibility for the lifetime of the SharedMemoryHandle.
+// responsibility for the lifetime of the SharedMemoryHandle. On success,
+// |*memory_handle| is set to a valid handle, |*size| is is set to the size of
+// that handle's underlying base::SharedMemory object, and
+// |*protection| indicates whether or not the handle may only be mapped
+// to a read-only memory segment.
+//
+// Note that if |*protection| is
+// |UnwrappedSharedMemoryHandleProtection::kReadOnly| upon return, writable
+// mapping of |*memory_handle| should not be attempted, and (unless there
+// is buggy code misusing WrapSharedMemoryHandle above) will always fail.
 MOJO_CPP_SYSTEM_EXPORT MojoResult
 UnwrapSharedMemoryHandle(ScopedSharedBufferHandle handle,
                          base::SharedMemoryHandle* memory_handle,
                          size_t* size,
-                         bool* read_only);
+                         UnwrappedSharedMemoryHandleProtection* protection);
 
 #if defined(OS_MACOSX) && !defined(OS_IOS)
 // Wraps a mach_port_t as a Mojo handle. This takes a reference to the
```


### `mojo/public/cpp/system/tests/BUILD.gn`

```diff
@@ -19,6 +19,7 @@ source_set("tests") {
   deps = [
     "//base",
     "//base/test:test_support",
+    "//mojo/edk/test:test_support",
     "//mojo/public/c/system/tests",
     "//mojo/public/cpp/system",
     "//mojo/public/cpp/test_support:test_utils",
```


### `ui/gfx/mojo/buffer_types_struct_traits.cc`

```diff
@@ -58,8 +58,9 @@ StructTraits<gfx::mojom::GpuMemoryBufferHandleDataView,
       handle.type != gfx::DXGI_SHARED_HANDLE &&
       handle.type != gfx::ANDROID_HARDWARE_BUFFER)
     return mojo::ScopedSharedBufferHandle();
-  return mojo::WrapSharedMemoryHandle(handle.handle, handle.handle.GetSize(),
-                                      false);
+  return mojo::WrapSharedMemoryHandle(
+      handle.handle, handle.handle.GetSize(),
+      mojo::UnwrappedSharedMemoryHandleProtection::kReadWrite);
 }
 
 const gfx::NativePixmapHandle&
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
