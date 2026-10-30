# Pacote de anotacao — caso 03

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

# Evidencia do caso 03

## Identificacao

- projeto: Chrome
- CVE: CVE-2013-0917
- CWE atribuida pelo BigVul: CWE-119
- commit: `02c8303512ebed345011f7b545e2f418799be2f0`
- URL do commit: https://github.com/chromium/chromium/commit/02c8303512ebed345011f7b545e2f418799be2f0
- arquivo da funcao marcada: `third_party/WebKit/Source/modules/filesystem/EntrySync.cpp`

## Mensagem do commit

> Oilpan: Ship Oilpan for SyncCallbackHelper, CreateFileResult and CallbackWrapper in filesystem/
> 
> These are leftovers when we shipped Oilpan for filesystem/ once.
> 
> BUG=340522
> 
> Review URL: https://codereview.chromium.org/501263003
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@180909 bbb929c8-8fbe-4397-9dbb-9b2b20218538

## Resumo da CVE

> The URL loader in Google Chrome before 26.0.1410.43 allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  Metadata* EntrySync::getMetadata(ExceptionState& exceptionState)
  {
-    RefPtr<MetadataSyncCallbackHelper> helper = MetadataSyncCallbackHelper::create();
+    MetadataSyncCallbackHelper* helper = MetadataSyncCallbackHelper::create();
      m_fileSystem->getMetadata(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
      return helper->getResult(exceptionState);
  }
```

## Corpo completo da funcao antes da correcao

```c
 Metadata* EntrySync::getMetadata(ExceptionState& exceptionState)
 {
    RefPtr<MetadataSyncCallbackHelper> helper = MetadataSyncCallbackHelper::create();
     m_fileSystem->getMetadata(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return helper->getResult(exceptionState);
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **8**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/WebKit/Source/modules/filesystem/DOMFileSystemSync.cpp` | modified | 7 | 15 |
| `third_party/WebKit/Source/modules/filesystem/DirectoryEntrySync.cpp` | modified | 3 | 3 |
| `third_party/WebKit/Source/modules/filesystem/EntrySync.cpp` **(funcao marcada esta aqui)** | modified | 4 | 4 |
| `third_party/WebKit/Source/modules/filesystem/FileWriterBase.h` | modified | 0 | 2 |
| `third_party/WebKit/Source/modules/filesystem/LocalFileSystem.cpp` | modified | 11 | 9 |
| `third_party/WebKit/Source/modules/filesystem/LocalFileSystem.h` | modified | 5 | 5 |
| `third_party/WebKit/Source/modules/filesystem/SyncCallbackHelper.h` | modified | 15 | 11 |
| `third_party/WebKit/Source/modules/filesystem/WorkerGlobalScopeFileSystem.cpp` | modified | 2 | 2 |


### `third_party/WebKit/Source/modules/filesystem/EntrySync.cpp`

```diff
@@ -52,28 +52,28 @@ EntrySync* EntrySync::create(EntryBase* entry)
 
 Metadata* EntrySync::getMetadata(ExceptionState& exceptionState)
 {
-    RefPtr<MetadataSyncCallbackHelper> helper = MetadataSyncCallbackHelper::create();
+    MetadataSyncCallbackHelper* helper = MetadataSyncCallbackHelper::create();
     m_fileSystem->getMetadata(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return helper->getResult(exceptionState);
 }
 
 EntrySync* EntrySync::moveTo(DirectoryEntrySync* parent, const String& name, ExceptionState& exceptionState) const
 {
-    RefPtr<EntrySyncCallbackHelper> helper = EntrySyncCallbackHelper::create();
+    EntrySyncCallbackHelper* helper = EntrySyncCallbackHelper::create();
     m_fileSystem->move(this, parent, name, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return helper->getResult(exceptionState);
 }
 
 EntrySync* EntrySync::copyTo(DirectoryEntrySync* parent, const String& name, ExceptionState& exceptionState) const
 {
-    RefPtr<EntrySyncCallbackHelper> helper = EntrySyncCallbackHelper::create();
+    EntrySyncCallbackHelper* helper = EntrySyncCallbackHelper::create();
     m_fileSystem->copy(this, parent, name, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return helper->getResult(exceptionState);
 }
 
 void EntrySync::remove(ExceptionState& exceptionState) const
 {
-    RefPtr<VoidSyncCallbackHelper> helper = VoidSyncCallbackHelper::create();
+    VoidSyncCallbackHelper* helper = VoidSyncCallbackHelper::create();
     m_fileSystem->remove(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     helper->getResult(exceptionState);
 }
```


### `third_party/WebKit/Source/modules/filesystem/DOMFileSystemSync.cpp`

```diff
@@ -79,11 +79,11 @@ namespace {
 
 class CreateFileHelper FINAL : public AsyncFileSystemCallbacks {
 public:
-    class CreateFileResult : public RefCountedWillBeGarbageCollected<CreateFileResult> {
+    class CreateFileResult : public GarbageCollectedFinalized<CreateFileResult> {
       public:
-        static PassRefPtrWillBeRawPtr<CreateFileResult> create()
+        static CreateFileResult* create()
         {
-            return adoptRefWillBeNoop(new CreateFileResult());
+            return new CreateFileResult();
         }
 
         bool m_failed;
@@ -101,17 +101,9 @@ class CreateFileHelper FINAL : public AsyncFileSystemCallbacks {
             , m_code(0)
         {
         }
-
-#if !ENABLE(OILPAN)
-        ~CreateFileResult()
-        {
-        }
-#endif
-
-        friend class RefCountedWillBeGarbageCollected<CreateFileResult>;
     };
 
-    static PassOwnPtr<AsyncFileSystemCallbacks> create(PassRefPtrWillBeRawPtr<CreateFileResult> result, const String& name, const KURL& url, FileSystemType type)
+    static PassOwnPtr<AsyncFileSystemCallbacks> create(CreateFileResult* result, const String& name, const KURL& url, FileSystemType type)
     {
         return adoptPtr(static_cast<AsyncFileSystemCallbacks*>(new CreateFileHelper(result, name, url, type)));
     }
@@ -155,15 +147,15 @@ class CreateFileHelper FINAL : public AsyncFileSystemCallbacks {
     }
 
 private:
-    CreateFileHelper(PassRefPtrWillBeRawPtr<CreateFileResult> result, const String& name, const KURL& url, FileSystemType type)
+    CreateFileHelper(CreateFileResult* result, const String& name, const KURL& url, FileSystemType type)
         : m_result(result)
         , m_name(name)
         , m_url(url)
         , m_type(type)
     {
     }
 
-    RefPtrWillBePersistent<CreateFileResult> m_result;
+    Persistent<CreateFileResult> m_result;
     String m_name;
     KURL m_url;
     FileSystemType m_type;
@@ -174,7 +166,7 @@ class CreateFileHelper FINAL : public AsyncFileSystemCallbacks {
 PassRefPtrWillBeRawPtr<File> DOMFileSystemSync::createFile(const FileEntrySync* fileEntry, ExceptionState& exceptionState)
 {
     KURL fileSystemURL = createFileSystemURL(fileEntry);
-    RefPtrWillBeRawPtr<CreateFileHelper::CreateFileResult> result(CreateFileHelper::CreateFileResult::create());
+    CreateFileHelper::CreateFileResult* result(CreateFileHelper::CreateFileResult::create());
     fileSystem()->createSnapshotFileAndReadMetadata(fileSystemURL, CreateFileHelper::create(result, fileEntry->name(), fileSystemURL, type()));
     if (result->m_failed) {
         exceptionState.throwDOMException(result->m_code, "Could not create '" + fileEntry->name() + "'.");
```


### `third_party/WebKit/Source/modules/filesystem/DirectoryEntrySync.cpp`

```diff
@@ -54,22 +54,22 @@ DirectoryReaderSync* DirectoryEntrySync::createReader()
 FileEntrySync* DirectoryEntrySync::getFile(const String& path, const Dictionary& options, ExceptionState& exceptionState)
 {
     FileSystemFlags flags(options);
-    RefPtr<EntrySyncCallbackHelper> helper = EntrySyncCallbackHelper::create();
+    EntrySyncCallbackHelper* helper = EntrySyncCallbackHelper::create();
     m_fileSystem->getFile(this, path, flags, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return static_cast<FileEntrySync*>(helper->getResult(exceptionState));
 }
 
 DirectoryEntrySync* DirectoryEntrySync::getDirectory(const String& path, const Dictionary& options, ExceptionState& exceptionState)
 {
     FileSystemFlags flags(options);
-    RefPtr<EntrySyncCallbackHelper> helper = EntrySyncCallbackHelper::create();
+    EntrySyncCallbackHelper* helper = EntrySyncCallbackHelper::create();
     m_fileSystem->getDirectory(this, path, flags, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     return static_cast<DirectoryEntrySync*>(helper->getResult(exceptionState));
 }
 
 void DirectoryEntrySync::removeRecursively(ExceptionState& exceptionState)
 {
-    RefPtr<VoidSyncCallbackHelper> helper = VoidSyncCallbackHelper::create();
+    VoidSyncCallbackHelper* helper = VoidSyncCallbackHelper::create();
     m_fileSystem->removeRecursively(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
     helper->getResult(exceptionState);
 }
```


### `third_party/WebKit/Source/modules/filesystem/FileWriterBase.h`

```diff
@@ -76,8 +76,6 @@ class FileWriterBase : public RefCountedGarbageCollectedWillBeGarbageCollectedFi
     void seekInternal(long long position);
 
 private:
-    friend class WTF::RefCounted<FileWriterBase>;
-
     OwnPtr<WebFileWriter> m_writer;
     long long m_position;
     long long m_length;
```


### `third_party/WebKit/Source/modules/filesystem/LocalFileSystem.cpp`

```diff
@@ -57,7 +57,7 @@ void reportFailure(ExecutionContext*, PassOwnPtr<AsyncFileSystemCallbacks> callb
 
 } // namespace
 
-class CallbackWrapper : public RefCounted<CallbackWrapper> {
+class CallbackWrapper FINAL : public GarbageCollectedFinalized<CallbackWrapper> {
 public:
     CallbackWrapper(PassOwnPtr<AsyncFileSystemCallbacks> c)
         : m_callbacks(c)
@@ -69,6 +69,8 @@ class CallbackWrapper : public RefCounted<CallbackWrapper> {
         return m_callbacks.release();
     }
 
+    void trace(Visitor*) { }
+
 private:
     OwnPtr<AsyncFileSystemCallbacks> m_callbacks;
 };
@@ -85,7 +87,7 @@ LocalFileSystem::~LocalFileSystem()
 void LocalFileSystem::resolveURL(ExecutionContext* context, const KURL& fileSystemURL, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
 {
     RefPtrWillBeRawPtr<ExecutionContext> contextPtr(context);
-    RefPtr<CallbackWrapper> wrapper = adoptRef(new CallbackWrapper(callbacks));
+    CallbackWrapper* wrapper = new CallbackWrapper(callbacks);
     requestFileSystemAccessInternal(context,
         bind(&LocalFileSystem::resolveURLInternal, this, contextPtr, fileSystemURL, wrapper),
         bind(&LocalFileSystem::fileSystemNotAllowedInternal, this, contextPtr, wrapper));
@@ -94,7 +96,7 @@ void LocalFileSystem::resolveURL(ExecutionContext* context, const KURL& fileSyst
 void LocalFileSystem::requestFileSystem(ExecutionContext* context, FileSystemType type, long long size, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
 {
     RefPtrWillBeRawPtr<ExecutionContext> contextPtr(context);
-    RefPtr<CallbackWrapper> wrapper = adoptRef(new CallbackWrapper(callbacks));
+    CallbackWrapper* wrapper = new CallbackWrapper(callbacks);
     requestFileSystemAccessInternal(context,
         bind(&LocalFileSystem::fileSystemAllowedInternal, this, contextPtr, type, wrapper),
         bind(&LocalFileSystem::fileSystemNotAllowedInternal, this, contextPtr, wrapper));
@@ -106,7 +108,7 @@ void LocalFileSystem::deleteFileSystem(ExecutionContext* context, FileSystemType
     ASSERT(context);
     ASSERT_WITH_SECURITY_IMPLICATION(context->isDocument());
 
-    RefPtr<CallbackWrapper> wrapper = adoptRef(new CallbackWrapper(callbacks));
+    CallbackWrapper* wrapper = new CallbackWrapper(callbacks);
     requestFileSystemAccessInternal(context,
         bind(&LocalFileSystem::deleteFileSystemInternal, this, contextPtr, type, wrapper),
         bind(&LocalFileSystem::fileSystemNotAllowedInternal, this, contextPtr, wrapper));
@@ -139,22 +141,22 @@ void LocalFileSystem::requestFileSystemAccessInternal(ExecutionContext* context,
 
 void LocalFileSystem::fileSystemNotAvailable(
     PassRefPtrWillBeRawPtr<ExecutionContext> context,
-    PassRefPtr<CallbackWrapper> callbacks)
+    CallbackWrapper* callbacks)
 {
     context->postTask(createCrossThreadTask(&reportFailure, callbacks->release(), FileError::ABORT_ERR));
 }
 
 void LocalFileSystem::fileSystemNotAllowedInternal(
     PassRefPtrWillBeRawPtr<ExecutionContext> context,
-    PassRefPtr<CallbackWrapper> callbacks)
+    CallbackWrapper* callbacks)
 {
     context->postTask(createCrossThreadTask(&reportFailure, callbacks->release(), FileError::ABORT_ERR));
 }
 
 void LocalFileSystem::fileSystemAllowedInternal(
     PassRefPtrWillBeRawPtr<ExecutionContext> context,
     FileSystemType type,
-    PassRefPtr<CallbackWrapper> callbacks)
+    CallbackWrapper* callbacks)
 {
     if (!fileSystem()) {
         fileSystemNotAvailable(context, callbacks);
@@ -168,7 +170,7 @@ void LocalFileSystem::fileSystemAllowedInternal(
 void LocalFileSystem::resolveURLInternal(
     PassRefPtrWillBeRawPtr<ExecutionContext> context,
     const KURL& fileSystemURL,
-    PassRefPtr<CallbackWrapper> callbacks)
+    CallbackWrapper* callbacks)
 {
     if (!fileSystem()) {
         fileSystemNotAvailable(context, callbacks);
@@ -180,7 +182,7 @@ void LocalFileSystem::resolveURLInternal(
 void LocalFileSystem::deleteFileSystemInternal(
     PassRefPtrWillBeRawPtr<ExecutionContext> context,
     FileSystemType type,
-    PassRefPtr<CallbackWrapper> callbacks)
+    CallbackWrapper* callbacks)
 {
     if (!fileSystem()) {
         fileSystemNotAvailable(context, callbacks);
```


### `third_party/WebKit/Source/modules/filesystem/LocalFileSystem.h`

```diff
@@ -74,11 +74,11 @@ class LocalFileSystem FINAL : public NoBaseWillBeGarbageCollectedFinalized<Local
 private:
     WebFileSystem* fileSystem() const;
     void requestFileSystemAccessInternal(ExecutionContext*, const Closure& allowed, const Closure& denied);
-    void fileSystemNotAvailable(PassRefPtrWillBeRawPtr<ExecutionContext>, PassRefPtr<CallbackWrapper>);
-    void fileSystemNotAllowedInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, PassRefPtr<CallbackWrapper>);
-    void fileSystemAllowedInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, FileSystemType, PassRefPtr<CallbackWrapper>);
-    void resolveURLInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, const KURL&, PassRefPtr<CallbackWrapper>);
-    void deleteFileSystemInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, FileSystemType, PassRefPtr<CallbackWrapper>);
+    void fileSystemNotAvailable(PassRefPtrWillBeRawPtr<ExecutionContext>, CallbackWrapper*);
+    void fileSystemNotAllowedInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, CallbackWrapper*);
+    void fileSystemAllowedInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, FileSystemType, CallbackWrapper*);
+    void resolveURLInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, const KURL&, CallbackWrapper*);
+    void deleteFileSystemInternal(PassRefPtrWillBeRawPtr<ExecutionContext>, FileSystemType, CallbackWrapper*);
     OwnPtr<FileSystemClient> m_client;
 };
 
```


### `third_party/WebKit/Source/modules/filesystem/SyncCallbackHelper.h`

```diff
@@ -45,7 +45,6 @@
 #include "modules/filesystem/MetadataCallback.h"
 #include "platform/heap/Handle.h"
 #include "wtf/PassRefPtr.h"
-#include "wtf/RefCounted.h"
 
 namespace blink {
 
@@ -54,7 +53,7 @@ struct HelperResultType {
     DISALLOW_ALLOCATION();
 public:
     typedef ResultType* ReturnType;
-    typedef Persistent<ResultType> StorageType;
+    typedef Member<ResultType> StorageType;
 
     static ReturnType createFromCallbackArg(CallbackArg argument)
     {
@@ -64,16 +63,16 @@ struct HelperResultType {
 
 // A helper template for FileSystemSync implementation.
 template <typename SuccessCallback, typename CallbackArg, typename ResultType>
-class SyncCallbackHelper FINAL : public RefCounted<SyncCallbackHelper<SuccessCallback, CallbackArg, ResultType> > {
+class SyncCallbackHelper FINAL : public GarbageCollected<SyncCallbackHelper<SuccessCallback, CallbackArg, ResultType> > {
 public:
     typedef SyncCallbackHelper<SuccessCallback, CallbackArg, ResultType> HelperType;
     typedef HelperResultType<ResultType, CallbackArg> ResultTypeTrait;
     typedef typename ResultTypeTrait::StorageType ResultStorageType;
     typedef typename ResultTypeTrait::ReturnType ResultReturnType;
 
-    static PassRefPtr<HelperType> create()
+    static HelperType* create()
     {
-        return adoptRef(new SyncCallbackHelper());
+        return new SyncCallbackHelper();
     }
 
     ResultReturnType getResult(ExceptionState& exceptionState)
@@ -87,6 +86,11 @@ class SyncCallbackHelper FINAL : public RefCounted<SyncCallbackHelper<SuccessCal
     PassOwnPtr<SuccessCallback> successCallback() { return SuccessCallbackImpl::create(this); }
     PassOwnPtr<ErrorCallback> errorCallback() { return ErrorCallbackImpl::create(this); }
 
+    void trace(Visitor* visitor)
+    {
+        visitor->trace(m_result);
+    }
+
 private:
     SyncCallbackHelper()
         : m_errorCode(FileError::OK)
@@ -96,7 +100,7 @@ class SyncCallbackHelper FINAL : public RefCounted<SyncCallbackHelper<SuccessCal
 
     class SuccessCallbackImpl FINAL : public SuccessCallback {
     public:
-        static PassOwnPtr<SuccessCallbackImpl> create(PassRefPtr<HelperType> helper)
+        static PassOwnPtr<SuccessCallbackImpl> create(HelperType* helper)
         {
             return adoptPtr(new SuccessCallbackImpl(helper));
         }
@@ -112,16 +116,16 @@ class SyncCallbackHelper FINAL : public RefCounted<SyncCallbackHelper<SuccessCal
         }
 
     private:
-        explicit SuccessCallbackImpl(PassRefPtr<HelperType> helper)
+        explicit SuccessCallbackImpl(HelperType* helper)
             : m_helper(helper)
         {
         }
-        RefPtr<HelperType> m_helper;
+        Persistent<HelperType> m_helper;
     };
 
     class ErrorCallbackImpl FINAL : public ErrorCallback {
     public:
-        static PassOwnPtr<ErrorCallbackImpl> create(PassRefPtr<HelperType> helper)
+        static PassOwnPtr<ErrorCallbackImpl> create(HelperType* helper)
         {
             return adoptPtr(new ErrorCallbackImpl(helper));
         }
@@ -133,11 +137,11 @@ class SyncCallbackHelper FINAL : public RefCounted<SyncCallbackHelper<SuccessCal
         }
 
     private:
-        explicit ErrorCallbackImpl(PassRefPtr<HelperType> helper)
+        explicit ErrorCallbackImpl(HelperType* helper)
             : m_helper(helper)
         {
         }
-        RefPtr<HelperType> m_helper;
+        Persistent<HelperType> m_helper;
     };
 
     void setError(FileError::ErrorCode code)
```


### `third_party/WebKit/Source/modules/filesystem/WorkerGlobalScopeFileSystem.cpp`

```diff
@@ -76,7 +76,7 @@ DOMFileSystemSync* WorkerGlobalScopeFileSystem::webkitRequestFileSystemSync(Work
         return 0;
     }
 
-    RefPtr<FileSystemSyncCallbackHelper> helper = FileSystemSyncCallbackHelper::create();
+    FileSystemSyncCallbackHelper* helper = FileSystemSyncCallbackHelper::create();
     OwnPtr<AsyncFileSystemCallbacks> callbacks = FileSystemCallbacks::create(helper->successCallback(), helper->errorCallback(), &worker, fileSystemType);
     callbacks->setShouldBlockUntilCompletion(true);
 
@@ -115,7 +115,7 @@ EntrySync* WorkerGlobalScopeFileSystem::webkitResolveLocalFileSystemSyncURL(Work
         return 0;
     }
 
-    RefPtr<EntrySyncCallbackHelper> resolveURLHelper = EntrySyncCallbackHelper::create();
+    EntrySyncCallbackHelper* resolveURLHelper = EntrySyncCallbackHelper::create();
     OwnPtr<AsyncFileSystemCallbacks> callbacks = ResolveURICallbacks::create(resolveURLHelper->successCallback(), resolveURLHelper->errorCallback(), &worker);
     callbacks->setShouldBlockUntilCompletion(true);
 
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
