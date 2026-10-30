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

- projeto: Chrome
- CVE: CVE-2015-1280
- CWE atribuida pelo BigVul: CWE-119
- commit: `bc1f34b9be509f1404f0bb1ba1947614d5f0bcd1`
- URL do commit: https://github.com/chromium/chromium/commit/bc1f34b9be509f1404f0bb1ba1947614d5f0bcd1
- arquivo da funcao marcada: `content/browser/media/media_interface_proxy.cc`

## Mensagem do commit

> media: Support hosting mojo CDM in a standalone service
> 
> Currently when mojo CDM is enabled it is hosted in the MediaService
> running in the process specified by "mojo_media_host". However, on
> some platforms we need to run mojo CDM and other mojo media services in
> different processes. For example, on desktop platforms, we want to run
> mojo video decoder in the GPU process, but run the mojo CDM in the
> utility process.
> 
> This CL adds a new build flag "enable_standalone_cdm_service". When
> enabled, the mojo CDM service will be hosted in a standalone "cdm"
> service running in the utility process. All other mojo media services
> will sill be hosted in the "media" servie running in the process
> specified by "mojo_media_host".
> 
> BUG=664364
> TEST=Encrypted media browser tests using mojo CDM is still working.
> 
> Change-Id: I95be6e05adc9ebcff966b26958ef1d7becdfb487
> Reviewed-on: https://chromium-review.googlesource.com/567172
> Commit-Queue: Xiaohan Wang <xhwang@chromium.org>
> Reviewed-by: Daniel Cheng <dcheng@chromium.org>
> Reviewed-by: John Abd-El-Malek <jam@chromium.org>
> Reviewed-by: Dan Sanders <sandersd@chromium.org>
> Cr-Commit-Position: refs/heads/master@{#486947}

## Resumo da CVE

> SkPictureShader.cpp in Skia, as used in Google Chrome before 44.0.2403.89, allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging access to a renderer process and providing crafted serialized data.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -3,7 +3,7 @@
    DCHECK(thread_checker_.CalledOnValidThread());
  
    if (!interface_factory_ptr_)
-    ConnectToService();
+    ConnectToMediaService();
  
    DCHECK(interface_factory_ptr_);
  
```

## Corpo completo da funcao antes da correcao

```c
MediaInterfaceProxy::GetMediaInterfaceFactory() {
  DVLOG(1) << __FUNCTION__;
   DCHECK(thread_checker_.CalledOnValidThread());
 
   if (!interface_factory_ptr_)
    ConnectToService();
 
   DCHECK(interface_factory_ptr_);
 
   return interface_factory_ptr_.get();
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **12**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `content/browser/media/media_interface_proxy.cc` **(funcao marcada esta aqui)** | modified | 59 | 10 |
| `content/browser/media/media_interface_proxy.h` | modified | 24 | 6 |
| `content/browser/service_manager/service_manager_context.cc` | modified | 8 | 2 |
| `content/common/service_manager/service_manager_connection_impl.cc` | modified | 2 | 1 |
| `content/public/app/BUILD.gn` | modified | 1 | 0 |
| `content/public/app/mojo/content_browser_manifest.json` | modified | 1 | 0 |
| `content/utility/utility_service_factory.cc` | modified | 4 | 4 |
| `media/media_options.gni` | modified | 6 | 3 |
| `media/mojo/BUILD.gn` | modified | 7 | 1 |
| `media/mojo/interfaces/constants.mojom` | modified | 4 | 0 |
| `media/mojo/services/BUILD.gn` | modified | 5 | 0 |
| `media/mojo/services/cdm_manifest.json` | added | 14 | 0 |


### `content/browser/media/media_interface_proxy.cc`

```diff
@@ -12,7 +12,6 @@
 #include "content/public/browser/render_frame_host.h"
 #include "content/public/common/content_client.h"
 #include "content/public/common/service_manager_connection.h"
-#include "media/mojo/features.h"
 #include "media/mojo/interfaces/constants.mojom.h"
 #include "media/mojo/interfaces/media_service.mojom.h"
 #include "media/mojo/services/media_interface_provider.h"
@@ -72,7 +71,7 @@ void MediaInterfaceProxy::CreateRenderer(
 void MediaInterfaceProxy::CreateCdm(
     media::mojom::ContentDecryptionModuleRequest request) {
   DCHECK(thread_checker_.CalledOnValidThread());
-  GetMediaInterfaceFactory()->CreateCdm(std::move(request));
+  GetCdmInterfaceFactory()->CreateCdm(std::move(request));
 }
 
 media::mojom::InterfaceFactory*
@@ -81,31 +80,52 @@ MediaInterfaceProxy::GetMediaInterfaceFactory() {
   DCHECK(thread_checker_.CalledOnValidThread());
 
   if (!interface_factory_ptr_)
-    ConnectToService();
+    ConnectToMediaService();
 
   DCHECK(interface_factory_ptr_);
 
   return interface_factory_ptr_.get();
 }
 
-void MediaInterfaceProxy::OnConnectionError() {
+media::mojom::InterfaceFactory* MediaInterfaceProxy::GetCdmInterfaceFactory() {
+  DVLOG(1) << __FUNCTION__;
+  DCHECK(thread_checker_.CalledOnValidThread());
+#if !BUILDFLAG(ENABLE_STANDALONE_CDM_SERVICE)
+  return GetMediaInterfaceFactory();
+#else
+  if (!cdm_interface_factory_ptr_)
+    ConnectToCdmService();
+
+  DCHECK(cdm_interface_factory_ptr_);
+
+  return cdm_interface_factory_ptr_.get();
+#endif
+}
+
+void MediaInterfaceProxy::OnMediaServiceConnectionError() {
   DVLOG(1) << __FUNCTION__;
   DCHECK(thread_checker_.CalledOnValidThread());
 
   interface_factory_ptr_.reset();
 }
 
-void MediaInterfaceProxy::ConnectToService() {
+void MediaInterfaceProxy::OnCdmServiceConnectionError() {
   DVLOG(1) << __FUNCTION__;
   DCHECK(thread_checker_.CalledOnValidThread());
-  DCHECK(!interface_factory_ptr_);
 
+  cdm_interface_factory_ptr_.reset();
+}
+
+service_manager::mojom::InterfaceProviderPtr
+MediaInterfaceProxy::GetFrameServices() {
   // Register frame services.
   service_manager::mojom::InterfaceProviderPtr interfaces;
+
   // TODO(xhwang): Replace this InterfaceProvider with a dedicated media host
   // interface. See http://crbug.com/660573
   auto provider = base::MakeUnique<media::MediaInterfaceProvider>(
       mojo::MakeRequest(&interfaces));
+
 #if BUILDFLAG(ENABLE_MOJO_CDM)
   // TODO(slan): Wrap these into a RenderFrame specific ProvisionFetcher impl.
   net::URLRequestContextGetter* context_getter =
@@ -115,20 +135,49 @@ void MediaInterfaceProxy::ConnectToService() {
   provider->registry()->AddInterface(base::Bind(
       &ProvisionFetcherImpl::Create, base::RetainedRef(context_getter)));
 #endif  // BUILDFLAG(ENABLE_MOJO_CDM)
+
   GetContentClient()->browser()->ExposeInterfacesToMediaService(
       provider->registry(), render_frame_host_);
 
   media_registries_.push_back(std::move(provider));
 
-  // TODO(slan): Use the BrowserContext Connector instead. See crbug.com/638950.
+  return interfaces;
+}
+
+void MediaInterfaceProxy::ConnectToMediaService() {
+  DVLOG(1) << __FUNCTION__;
+
   media::mojom::MediaServicePtr media_service;
+
+  // TODO(slan): Use the BrowserContext Connector instead. See crbug.com/638950.
   service_manager::Connector* connector =
       ServiceManagerConnection::GetForProcess()->GetConnector();
   connector->BindInterface(media::mojom::kMediaServiceName, &media_service);
+
   media_service->CreateInterfaceFactory(MakeRequest(&interface_factory_ptr_),
-                                        std::move(interfaces));
-  interface_factory_ptr_.set_connection_error_handler(base::Bind(
-      &MediaInterfaceProxy::OnConnectionError, base::Unretained(this)));
+                                        GetFrameServices());
+
+  interface_factory_ptr_.set_connection_error_handler(
+      base::Bind(&MediaInterfaceProxy::OnMediaServiceConnectionError,
+                 base::Unretained(this)));
+}
+
+void MediaInterfaceProxy::ConnectToCdmService() {
+  DVLOG(1) << __FUNCTION__;
+
+  media::mojom::MediaServicePtr media_service;
+
+  // TODO(slan): Use the BrowserContext Connector instead. See crbug.com/638950.
+  service_manager::Connector* connector =
+      ServiceManagerConnection::GetForProcess()->GetConnector();
+  connector->BindInterface(media::mojom::kCdmServiceName, &media_service);
+
+  media_service->CreateInterfaceFactory(
+      MakeRequest(&cdm_interface_factory_ptr_), GetFrameServices());
+
+  cdm_interface_factory_ptr_.set_connection_error_handler(
+      base::Bind(&MediaInterfaceProxy::OnCdmServiceConnectionError,
+                 base::Unretained(this)));
 }
 
 }  // namespace content
```


### `content/browser/media/media_interface_proxy.h`

```diff
@@ -10,8 +10,10 @@
 
 #include "base/macros.h"
 #include "base/threading/thread_checker.h"
+#include "media/mojo/features.h"
 #include "media/mojo/interfaces/interface_factory.mojom.h"
 #include "mojo/public/cpp/bindings/binding.h"
+#include "services/service_manager/public/interfaces/interface_provider.mojom.h"
 
 namespace media {
 class MediaInterfaceProvider;
@@ -27,8 +29,8 @@ class RenderFrameHost;
 class MediaInterfaceProxy : public media::mojom::InterfaceFactory {
  public:
   // Constructs MediaInterfaceProxy and bind |this| to the |request|. When
-  // connection error happens on the client interface, |error_handler| should be
-  // fired.
+  // connection error happens on the client interface, |error_handler| will be
+  // called, which could destroy |this|.
   MediaInterfaceProxy(RenderFrameHost* render_frame_host,
                       media::mojom::InterfaceFactoryRequest request,
                       const base::Closure& error_handler);
@@ -42,12 +44,21 @@ class MediaInterfaceProxy : public media::mojom::InterfaceFactory {
   void CreateCdm(media::mojom::ContentDecryptionModuleRequest request) final;
 
  private:
+  // Get the |interface_factory_ptr_|.
   media::mojom::InterfaceFactory* GetMediaInterfaceFactory();
 
-  // Callback for connection error on |interface_factory_ptr_|.
-  void OnConnectionError();
+  // Get the |cdm_interface_factory_ptr_|.
+  media::mojom::InterfaceFactory* GetCdmInterfaceFactory();
 
-  void ConnectToService();
+  // Callback for connection error from |interface_factory_ptr_| or
+  // |cdm_interface_factory_ptr_|.
+  void OnMediaServiceConnectionError();
+  void OnCdmServiceConnectionError();
+
+  service_manager::mojom::InterfaceProviderPtr GetFrameServices();
+
+  void ConnectToMediaService();
+  void ConnectToCdmService();
 
   // Safe to hold a raw pointer since |this| is owned by RenderFrameHostImpl.
   RenderFrameHost* render_frame_host_;
@@ -58,9 +69,16 @@ class MediaInterfaceProxy : public media::mojom::InterfaceFactory {
 
   mojo::Binding<media::mojom::InterfaceFactory> binding_;
 
-  // InterfacePtr to the remote media::mojom::InterfaceFactory implementation.
+  // InterfacePtr to the remote media::mojom::InterfaceFactory implementation
+  // in the service named kMediaServiceName hosted in the process specified by
+  // the "mojo_media_host" gn argument. Available options are browser, GPU and
+  // utility processes.
   media::mojom::InterfaceFactoryPtr interface_factory_ptr_;
 
+  // InterfacePtr to the remote media::mojom::InterfaceFactory implementation
+  // in the service named kCdmServiceName hosted in the utility process.
+  media::mojom::InterfaceFactoryPtr cdm_interface_factory_ptr_;
+
   base::ThreadChecker thread_checker_;
 
   DISALLOW_COPY_AND_ASSIGN(MediaInterfaceProxy);
```


### `content/browser/service_manager/service_manager_context.cc`

```diff
@@ -357,11 +357,17 @@ ServiceManagerContext::ServiceManagerContext() {
   }
 
 #if BUILDFLAG(ENABLE_MOJO_MEDIA_IN_UTILITY_PROCESS)
+  out_of_process_services[media::mojom::kMediaServiceName] = {
+      base::ASCIIToUTF16("Media Service"), SANDBOX_TYPE_UTILITY};
+#endif
+
+#if BUILDFLAG(ENABLE_STANDALONE_CDM_SERVICE)
   // TODO(xhwang): This is only used for test/experiment for now so it's okay
   // to run it in an unsandboxed utility process. Fix CDM loading so that we can
   // run it in the sandboxed utility process. See http://crbug.com/510604
-  out_of_process_services[media::mojom::kMediaServiceName] = {
-      base::ASCIIToUTF16("Media Service"), SANDBOX_TYPE_NO_SANDBOX};
+  out_of_process_services[media::mojom::kCdmServiceName] = {
+      base::ASCIIToUTF16("Content Decryption Module Service"),
+      SANDBOX_TYPE_NO_SANDBOX};
 #endif
 
   for (const auto& service : out_of_process_services) {
```


### `content/common/service_manager/service_manager_connection_impl.cc`

```diff
@@ -238,7 +238,8 @@ class ServiceManagerConnectionImpl::IOThreadContext
       const ServiceRequestHandler& handler) {
     DCHECK(io_thread_checker_.CalledOnValidThread());
     auto result = request_handlers_.insert(std::make_pair(name, handler));
-    DCHECK(result.second);
+    DCHECK(result.second) << "ServiceRequestHandler for " << name
+                          << " already exists.";
   }
 
   /////////////////////////////////////////////////////////////////////////////
```


### `content/public/app/BUILD.gn`

```diff
@@ -182,6 +182,7 @@ service_manifest("packaged_services_manifest") {
   source = "mojo/content_packaged_services_manifest.json"
   packaged_services = [
     "//content/network:manifest",
+    "//media/mojo/services:cdm_manifest",
     "//media/mojo/services:media_manifest",
     "//services/data_decoder:manifest",
     "//services/device:manifest",
```


### `content/public/app/mojo/content_browser_manifest.json`

```diff
@@ -60,6 +60,7 @@
       },
       "requires": {
         "*": [ "app" ],
+        "cdm": [ "media:cdm" ],
         // In classic ash, the browser supplies ash interfaces to itself.
         "content_browser": [
           "ash",
```


### `content/utility/utility_service_factory.cc`

```diff
@@ -47,7 +47,7 @@ namespace {
 
 #if BUILDFLAG(ENABLE_PEPPER_CDMS)
 
-static_assert(BUILDFLAG(ENABLE_MOJO_MEDIA_IN_UTILITY_PROCESS), "");
+static_assert(BUILDFLAG(ENABLE_STANDALONE_CDM_SERVICE), "");
 static_assert(BUILDFLAG(ENABLE_MOJO_CDM), "");
 
 std::unique_ptr<media::CdmAllocator> CreateCdmAllocator() {
@@ -66,7 +66,7 @@ class CdmMojoMediaClient final : public media::MojoMediaClient {
   }
 };
 
-std::unique_ptr<service_manager::Service> CreateMediaService() {
+std::unique_ptr<service_manager::Service> CreateCdmService() {
   return std::unique_ptr<service_manager::Service>(
       new ::media::MediaService(base::MakeUnique<CdmMojoMediaClient>()));
 }
@@ -94,8 +94,8 @@ void UtilityServiceFactory::RegisterServices(ServiceMap* services) {
 
 #if BUILDFLAG(ENABLE_PEPPER_CDMS)
   service_manager::EmbeddedServiceInfo info;
-  info.factory = base::Bind(&CreateMediaService);
-  services->insert(std::make_pair(media::mojom::kMediaServiceName, info));
+  info.factory = base::Bind(&CreateCdmService);
+  services->insert(std::make_pair(media::mojom::kCdmServiceName, info));
 #endif
 
   service_manager::EmbeddedServiceInfo shape_detection_info;
```


### `media/media_options.gni`

```diff
@@ -149,6 +149,11 @@ declare_args() {
   # - "utility": Use mojo media service hosted in the utility process.
   mojo_media_host = "none"
 
+  # Force to host the CDM service in standalone "cdm" service instead of the
+  # "media" service hosted in the process specified by "mojo_media_host". Other
+  # mojo media services will not be affected.
+  enable_standalone_cdm_service = false
+
   # Default mojo_media_services and mojo_media_host on various platforms.
   # Can be overridden by gn build arguments from the --args command line flag
   # for local testing.
@@ -167,10 +172,8 @@ declare_args() {
       ]
       mojo_media_host = "gpu"
     } else if (enable_pepper_cdms) {
-      # TODO(xhwang): Also support running "video_decoder" service in the "gpu"
-      # process. See http://crbug.com/664364
       mojo_media_services = [ "cdm" ]
-      mojo_media_host = "utility"
+      enable_standalone_cdm_service = true
     }
   }
 }
```


### `media/mojo/BUILD.gn`

```diff
@@ -46,11 +46,16 @@ buildflag_header("features") {
       enable_mojo_media_in_gpu_process = true
     } else if (mojo_media_host == "utility") {
       enable_mojo_media_in_utility_process = true
-    } else {
+    } else if (!enable_standalone_cdm_service) {
       assert(false, "Invalid mojo media host: $mojo_media_host")
     }
   }
 
+  if (enable_standalone_cdm_service) {
+    assert(enable_mojo_cdm,
+           "Mojo CDM must be enabled to run in standalone CDM service.")
+  }
+
   flags = [
     "ENABLE_MOJO_MEDIA=$enable_mojo_media",
     "ENABLE_TEST_MOJO_MEDIA_CLIENT=$enable_test_mojo_media_client",
@@ -61,6 +66,7 @@ buildflag_header("features") {
     "ENABLE_MOJO_MEDIA_IN_BROWSER_PROCESS=$enable_mojo_media_in_browser_process",
     "ENABLE_MOJO_MEDIA_IN_GPU_PROCESS=$enable_mojo_media_in_gpu_process",
     "ENABLE_MOJO_MEDIA_IN_UTILITY_PROCESS=$enable_mojo_media_in_utility_process",
+    "ENABLE_STANDALONE_CDM_SERVICE=$enable_standalone_cdm_service",
   ]
 }
 
```


### `media/mojo/interfaces/constants.mojom`

```diff
@@ -8,3 +8,7 @@ module media.mojom;
 // the |mojo_media_host| gn variable. This must match the name in
 // media/mojo/services/media_manifest.json
 const string kMediaServiceName = "media";
+
+// The default service name for MediaService hosting only the CDM service.
+// This must match the name in media/mojo/services/cdm_manifest.json
+const string kCdmServiceName = "cdm";
```


### `media/mojo/services/BUILD.gn`

```diff
@@ -140,6 +140,11 @@ service_test("media_service_unittests") {
   ]
 }
 
+service_manifest("cdm_manifest") {
+  name = "cdm"
+  source = "cdm_manifest.json"
+}
+
 service_manifest("media_manifest") {
   name = "media"
   source = "media_manifest.json"
```


### `media/mojo/services/cdm_manifest.json`

```diff
@@ -0,0 +1,14 @@
+{
+  "name": "cdm",
+  "display_name": "Content Decryption Module Service",
+  "interface_provider_specs": {
+    "service_manager:connector": {
+      "provides": {
+        "media:cdm": [ "media::mojom::MediaService" ]
+      },
+      "requires": {
+        "*": [ "app" ]
+      }
+    }
+  }
+}
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
