# Pacote de anotacao — caso 12

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

# Evidencia do caso 12

## Identificacao

- projeto: Chrome
- CVE: CVE-2017-5112
- CWE atribuida pelo BigVul: CWE-119
- commit: `f6ac1dba5e36f338a490752a2cbef3339096d9fe`
- URL do commit: https://github.com/chromium/chromium/commit/f6ac1dba5e36f338a490752a2cbef3339096d9fe
- arquivo da funcao marcada: `third_party/WebKit/Source/platform/graphics/gpu/DrawingBuffer.cpp`

## Mensagem do commit

> Reset ES3 pixel pack parameters and PIXEL_PACK_BUFFER binding in DrawingBuffer before ReadPixels() and recover them later.
> 
> BUG=740603
> TEST=new conformance test
> R=kbr@chromium.org,piman@chromium.org
> 
> Change-Id: I3ea54c6cc34f34e249f7c8b9f792d93c5e1958f4
> Reviewed-on: https://chromium-review.googlesource.com/570840
> Reviewed-by: Antoine Labour <piman@chromium.org>
> Reviewed-by: Kenneth Russell <kbr@chromium.org>
> Commit-Queue: Zhenyao Mo <zmo@chromium.org>
> Cr-Commit-Position: refs/heads/master@{#486518}

## Resumo da CVE

> Heap buffer overflow in WebGL in Google Chrome prior to 61.0.3163.79 for Windows allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -8,7 +8,7 @@
      bool want_stencil_buffer,
      bool want_antialiasing,
      PreserveDrawingBuffer preserve,
-    WebGLVersion web_gl_version,
+    WebGLVersion webgl_version,
      ChromiumImageUsage chromium_image_usage,
      const CanvasColorParams& color_params) {
    DCHECK(context_provider);
@@ -50,7 +50,7 @@
    RefPtr<DrawingBuffer> drawing_buffer = AdoptRef(new DrawingBuffer(
        std::move(context_provider), std::move(extensions_util), client,
        discard_framebuffer_supported, want_alpha_channel, premultiplied_alpha,
-      preserve, web_gl_version, want_depth_buffer, want_stencil_buffer,
+      preserve, webgl_version, want_depth_buffer, want_stencil_buffer,
        chromium_image_usage, color_params));
    if (!drawing_buffer->Initialize(size, multisample_supported)) {
      drawing_buffer->BeginDestruction();
```

## Corpo completo da funcao antes da correcao

```c
PassRefPtr<DrawingBuffer> DrawingBuffer::Create(
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    Client* client,
    const IntSize& size,
    bool premultiplied_alpha,
    bool want_alpha_channel,
    bool want_depth_buffer,
     bool want_stencil_buffer,
     bool want_antialiasing,
     PreserveDrawingBuffer preserve,
    WebGLVersion web_gl_version,
     ChromiumImageUsage chromium_image_usage,
     const CanvasColorParams& color_params) {
   DCHECK(context_provider);

  if (g_should_fail_drawing_buffer_creation_for_testing) {
    g_should_fail_drawing_buffer_creation_for_testing = false;
    return nullptr;
  }

  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(context_provider->ContextGL());
  if (!extensions_util->IsValid()) {
    return nullptr;
  }
  DCHECK(extensions_util->SupportsExtension("GL_OES_packed_depth_stencil"));
  extensions_util->EnsureExtensionEnabled("GL_OES_packed_depth_stencil");
  bool multisample_supported =
      want_antialiasing &&
      (extensions_util->SupportsExtension(
           "GL_CHROMIUM_framebuffer_multisample") ||
       extensions_util->SupportsExtension(
           "GL_EXT_multisampled_render_to_texture")) &&
      extensions_util->SupportsExtension("GL_OES_rgb8_rgba8");
  if (multisample_supported) {
    extensions_util->EnsureExtensionEnabled("GL_OES_rgb8_rgba8");
    if (extensions_util->SupportsExtension(
            "GL_CHROMIUM_framebuffer_multisample"))
      extensions_util->EnsureExtensionEnabled(
          "GL_CHROMIUM_framebuffer_multisample");
    else
      extensions_util->EnsureExtensionEnabled(
          "GL_EXT_multisampled_render_to_texture");
  }
  bool discard_framebuffer_supported =
      extensions_util->SupportsExtension("GL_EXT_discard_framebuffer");
  if (discard_framebuffer_supported)
    extensions_util->EnsureExtensionEnabled("GL_EXT_discard_framebuffer");

   RefPtr<DrawingBuffer> drawing_buffer = AdoptRef(new DrawingBuffer(
       std::move(context_provider), std::move(extensions_util), client,
       discard_framebuffer_supported, want_alpha_channel, premultiplied_alpha,
      preserve, web_gl_version, want_depth_buffer, want_stencil_buffer,
       chromium_image_usage, color_params));
   if (!drawing_buffer->Initialize(size, multisample_supported)) {
     drawing_buffer->BeginDestruction();
    return PassRefPtr<DrawingBuffer>();
  }
  return drawing_buffer;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **7**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/WebKit/Source/modules/webgl/WebGL2RenderingContextBase.cpp` | modified | 20 | 0 |
| `third_party/WebKit/Source/modules/webgl/WebGL2RenderingContextBase.h` | modified | 2 | 0 |
| `third_party/WebKit/Source/modules/webgl/WebGLRenderingContextBase.cpp` | modified | 4 | 1 |
| `third_party/WebKit/Source/modules/webgl/WebGLRenderingContextBase.h` | modified | 2 | 1 |
| `third_party/WebKit/Source/platform/graphics/gpu/DrawingBuffer.cpp` **(funcao marcada esta aqui)** | modified | 21 | 10 |
| `third_party/WebKit/Source/platform/graphics/gpu/DrawingBuffer.h` | modified | 11 | 4 |
| `third_party/WebKit/Source/platform/graphics/gpu/DrawingBufferTestHelpers.h` | modified | 18 | 3 |


### `third_party/WebKit/Source/platform/graphics/gpu/DrawingBuffer.cpp`

```diff
@@ -76,7 +76,7 @@ PassRefPtr<DrawingBuffer> DrawingBuffer::Create(
     bool want_stencil_buffer,
     bool want_antialiasing,
     PreserveDrawingBuffer preserve,
-    WebGLVersion web_gl_version,
+    WebGLVersion webgl_version,
     ChromiumImageUsage chromium_image_usage,
     const CanvasColorParams& color_params) {
   DCHECK(context_provider);
@@ -119,7 +119,7 @@ PassRefPtr<DrawingBuffer> DrawingBuffer::Create(
   RefPtr<DrawingBuffer> drawing_buffer = AdoptRef(new DrawingBuffer(
       std::move(context_provider), std::move(extensions_util), client,
       discard_framebuffer_supported, want_alpha_channel, premultiplied_alpha,
-      preserve, web_gl_version, want_depth_buffer, want_stencil_buffer,
+      preserve, webgl_version, want_depth_buffer, want_stencil_buffer,
       chromium_image_usage, color_params));
   if (!drawing_buffer->Initialize(size, multisample_supported)) {
     drawing_buffer->BeginDestruction();
@@ -140,14 +140,14 @@ DrawingBuffer::DrawingBuffer(
     bool want_alpha_channel,
     bool premultiplied_alpha,
     PreserveDrawingBuffer preserve,
-    WebGLVersion web_gl_version,
+    WebGLVersion webgl_version,
     bool want_depth,
     bool want_stencil,
     ChromiumImageUsage chromium_image_usage,
     const CanvasColorParams& color_params)
     : client_(client),
       preserve_drawing_buffer_(preserve),
-      web_gl_version_(web_gl_version),
+      webgl_version_(webgl_version),
       context_provider_(WTF::WrapUnique(new WebGraphicsContext3DProviderWrapper(
           std::move(context_provider)))),
       gl_(this->ContextProvider()->ContextGL()),
@@ -340,7 +340,7 @@ bool DrawingBuffer::FinishPrepareTextureMailboxGpu(
     viz::TextureMailbox* out_mailbox,
     std::unique_ptr<cc::SingleReleaseCallback>* out_release_callback) {
   DCHECK(state_restorer_);
-  if (web_gl_version_ > kWebGL1) {
+  if (webgl_version_ > kWebGL1) {
     state_restorer_->SetPixelUnpackBufferBindingDirty();
     gl_->BindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
   }
@@ -671,7 +671,7 @@ bool DrawingBuffer::Initialize(const IntSize& size, bool use_multisampling) {
   // textures only if ScreenSpaceAntialiasing is enabled, because
   // ScreenSpaceAntialiasing is much faster with storage textures.
   storage_texture_supported_ =
-      (web_gl_version_ > kWebGL1 ||
+      (webgl_version_ > kWebGL1 ||
        extensions_util_->SupportsExtension("GL_EXT_texture_storage")) &&
       anti_aliasing_mode_ == kScreenSpaceAntialiasing;
   sample_count_ = std::min(4, max_sample_count);
@@ -1038,11 +1038,12 @@ void DrawingBuffer::RestoreFramebufferBindings() {
 void DrawingBuffer::RestoreAllState() {
   client_->DrawingBufferClientRestoreScissorTest();
   client_->DrawingBufferClientRestoreMaskAndClearValues();
-  client_->DrawingBufferClientRestorePixelPackAlignment();
+  client_->DrawingBufferClientRestorePixelPackParameters();
   client_->DrawingBufferClientRestoreTexture2DBinding();
   client_->DrawingBufferClientRestoreRenderbufferBinding();
   client_->DrawingBufferClientRestoreFramebufferBinding();
   client_->DrawingBufferClientRestorePixelUnpackBufferBinding();
+  client_->DrawingBufferClientRestorePixelPackBufferBinding();
 }
 
 bool DrawingBuffer::Multisample() const {
@@ -1106,8 +1107,16 @@ void DrawingBuffer::ReadBackFramebuffer(unsigned char* pixels,
                                         ReadbackOrder readback_order,
                                         WebGLImageConversion::AlphaOp op) {
   DCHECK(state_restorer_);
-  state_restorer_->SetPixelPackAlignmentDirty();
+  state_restorer_->SetPixelPackParametersDirty();
   gl_->PixelStorei(GL_PACK_ALIGNMENT, 1);
+  if (webgl_version_ > kWebGL1) {
+    gl_->PixelStorei(GL_PACK_SKIP_ROWS, 0);
+    gl_->PixelStorei(GL_PACK_SKIP_PIXELS, 0);
+    gl_->PixelStorei(GL_PACK_ROW_LENGTH, 0);
+
+    state_restorer_->SetPixelPackBufferBindingDirty();
+    gl_->BindBuffer(GL_PIXEL_PACK_BUFFER, 0);
+  }
   gl_->ReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
 
   size_t buffer_size = 4 * width * height;
@@ -1371,8 +1380,8 @@ DrawingBuffer::ScopedStateRestorer::~ScopedStateRestorer() {
     client->DrawingBufferClientRestoreScissorTest();
     client->DrawingBufferClientRestoreMaskAndClearValues();
   }
-  if (pixel_pack_alignment_dirty_)
-    client->DrawingBufferClientRestorePixelPackAlignment();
+  if (pixel_pack_parameters_dirty_)
+    client->DrawingBufferClientRestorePixelPackParameters();
   if (texture_binding_dirty_)
     client->DrawingBufferClientRestoreTexture2DBinding();
   if (renderbuffer_binding_dirty_)
@@ -1381,6 +1390,8 @@ DrawingBuffer::ScopedStateRestorer::~ScopedStateRestorer() {
     client->DrawingBufferClientRestoreFramebufferBinding();
   if (pixel_unpack_buffer_binding_dirty_)
     client->DrawingBufferClientRestorePixelUnpackBufferBinding();
+  if (pixel_pack_buffer_binding_dirty_)
+    client->DrawingBufferClientRestorePixelPackBufferBinding();
 }
 
 bool DrawingBuffer::ShouldUseChromiumImage() {
```


### `third_party/WebKit/Source/modules/webgl/WebGL2RenderingContextBase.cpp`

```diff
@@ -5748,4 +5748,24 @@ void WebGL2RenderingContextBase::
                           ObjectOrZero(bound_pixel_unpack_buffer_.Get()));
 }
 
+void WebGL2RenderingContextBase::
+    DrawingBufferClientRestorePixelPackBufferBinding() {
+  if (!ContextGL())
+    return;
+  ContextGL()->BindBuffer(GL_PIXEL_PACK_BUFFER,
+                          ObjectOrZero(bound_pixel_pack_buffer_.Get()));
+}
+
+void WebGL2RenderingContextBase::
+    DrawingBufferClientRestorePixelPackParameters() {
+  if (!ContextGL())
+    return;
+
+  ContextGL()->PixelStorei(GL_PACK_ROW_LENGTH, pack_row_length_);
+  ContextGL()->PixelStorei(GL_PACK_SKIP_ROWS, pack_skip_rows_);
+  ContextGL()->PixelStorei(GL_PACK_SKIP_PIXELS, pack_skip_pixels_);
+
+  WebGLRenderingContextBase::DrawingBufferClientRestorePixelPackParameters();
+}
+
 }  // namespace blink
```


### `third_party/WebKit/Source/modules/webgl/WebGL2RenderingContextBase.h`

```diff
@@ -989,6 +989,8 @@ class WebGL2RenderingContextBase : public WebGLRenderingContextBase {
 
   // DrawingBuffer::Client implementation.
   void DrawingBufferClientRestorePixelUnpackBufferBinding() override;
+  void DrawingBufferClientRestorePixelPackBufferBinding() override;
+  void DrawingBufferClientRestorePixelPackParameters() override;
 
   // Helper function to validate target and the attachment combination for
   // getFramebufferAttachmentParameters.  Generate GL error and return false if
```


### `third_party/WebKit/Source/modules/webgl/WebGLRenderingContextBase.cpp`

```diff
@@ -6344,7 +6344,8 @@ void WebGLRenderingContextBase::DrawingBufferClientRestoreMaskAndClearValues() {
   ContextGL()->ClearStencil(clear_stencil_);
 }
 
-void WebGLRenderingContextBase::DrawingBufferClientRestorePixelPackAlignment() {
+void WebGLRenderingContextBase::
+    DrawingBufferClientRestorePixelPackParameters() {
   if (!ContextGL())
     return;
   ContextGL()->PixelStorei(GL_PACK_ALIGNMENT, pack_alignment_);
@@ -6372,6 +6373,8 @@ void WebGLRenderingContextBase::DrawingBufferClientRestoreFramebufferBinding() {
 
 void WebGLRenderingContextBase::
     DrawingBufferClientRestorePixelUnpackBufferBinding() {}
+void WebGLRenderingContextBase::
+    DrawingBufferClientRestorePixelPackBufferBinding() {}
 
 ScriptValue WebGLRenderingContextBase::GetBooleanParameter(
     ScriptState* script_state,
```


### `third_party/WebKit/Source/modules/webgl/WebGLRenderingContextBase.h`

```diff
@@ -642,11 +642,12 @@ class MODULES_EXPORT WebGLRenderingContextBase : public CanvasRenderingContext,
   bool DrawingBufferClientIsBoundForDraw() override;
   void DrawingBufferClientRestoreScissorTest() override;
   void DrawingBufferClientRestoreMaskAndClearValues() override;
-  void DrawingBufferClientRestorePixelPackAlignment() override;
+  void DrawingBufferClientRestorePixelPackParameters() override;
   void DrawingBufferClientRestoreTexture2DBinding() override;
   void DrawingBufferClientRestoreRenderbufferBinding() override;
   void DrawingBufferClientRestoreFramebufferBinding() override;
   void DrawingBufferClientRestorePixelUnpackBufferBinding() override;
+  void DrawingBufferClientRestorePixelPackBufferBinding() override;
 
   virtual void DestroyContext();
   void MarkContextChanged(ContentChangeType);
```


### `third_party/WebKit/Source/platform/graphics/gpu/DrawingBuffer.h`

```diff
@@ -89,12 +89,15 @@ class PLATFORM_EXPORT DrawingBuffer
     virtual void DrawingBufferClientRestoreScissorTest() = 0;
     // Restores the mask and clear value for color, depth, and stencil buffers.
     virtual void DrawingBufferClientRestoreMaskAndClearValues() = 0;
-    virtual void DrawingBufferClientRestorePixelPackAlignment() = 0;
+    // Assume client knows the GL/WebGL version and restore necessary params
+    // accordingly.
+    virtual void DrawingBufferClientRestorePixelPackParameters() = 0;
     // Restores the GL_TEXTURE_2D binding for the active texture unit only.
     virtual void DrawingBufferClientRestoreTexture2DBinding() = 0;
     virtual void DrawingBufferClientRestoreRenderbufferBinding() = 0;
     virtual void DrawingBufferClientRestoreFramebufferBinding() = 0;
     virtual void DrawingBufferClientRestorePixelUnpackBufferBinding() = 0;
+    virtual void DrawingBufferClientRestorePixelPackBufferBinding() = 0;
   };
 
   enum PreserveDrawingBuffer {
@@ -279,24 +282,28 @@ class PLATFORM_EXPORT DrawingBuffer
 
     // Mark parts of the state that are dirty and need to be restored.
     void SetClearStateDirty() { clear_state_dirty_ = true; }
-    void SetPixelPackAlignmentDirty() { pixel_pack_alignment_dirty_ = true; }
+    void SetPixelPackParametersDirty() { pixel_pack_parameters_dirty_ = true; }
     void SetTextureBindingDirty() { texture_binding_dirty_ = true; }
     void SetRenderbufferBindingDirty() { renderbuffer_binding_dirty_ = true; }
     void SetFramebufferBindingDirty() { framebuffer_binding_dirty_ = true; }
     void SetPixelUnpackBufferBindingDirty() {
       pixel_unpack_buffer_binding_dirty_ = true;
     }
+    void SetPixelPackBufferBindingDirty() {
+      pixel_pack_buffer_binding_dirty_ = true;
+    }
 
    private:
     RefPtr<DrawingBuffer> drawing_buffer_;
     // The previous state restorer, in case restorers are nested.
     ScopedStateRestorer* previous_state_restorer_ = nullptr;
     bool clear_state_dirty_ = false;
-    bool pixel_pack_alignment_dirty_ = false;
+    bool pixel_pack_parameters_dirty_ = false;
     bool texture_binding_dirty_ = false;
     bool renderbuffer_binding_dirty_ = false;
     bool framebuffer_binding_dirty_ = false;
     bool pixel_unpack_buffer_binding_dirty_ = false;
+    bool pixel_pack_buffer_binding_dirty_ = false;
   };
 
   // All parameters necessary to generate the texture for the ColorBuffer.
@@ -457,7 +464,7 @@ class PLATFORM_EXPORT DrawingBuffer
   Client* client_ = nullptr;
 
   const PreserveDrawingBuffer preserve_drawing_buffer_;
-  const WebGLVersion web_gl_version_;
+  const WebGLVersion webgl_version_;
 
   std::unique_ptr<WebGraphicsContext3DProviderWrapper> context_provider_;
   // Lifetime is tied to the m_contextProvider.
```


### `third_party/WebKit/Source/platform/graphics/gpu/DrawingBufferTestHelpers.h`

```diff
@@ -147,8 +147,16 @@ class GLES2InterfaceForTests : public gpu::gles2::GLES2InterfaceStub,
   }
 
   void BindBuffer(GLenum target, GLuint buffer) override {
-    if (target == GL_PIXEL_UNPACK_BUFFER)
-      state_.pixel_unpack_buffer_binding = buffer;
+    switch (target) {
+      case GL_PIXEL_UNPACK_BUFFER:
+        state_.pixel_unpack_buffer_binding = buffer;
+        break;
+      case GL_PIXEL_PACK_BUFFER:
+        state_.pixel_pack_buffer_binding = buffer;
+        break;
+      default:
+        break;
+    }
   }
 
   GLuint64 InsertFenceSyncCHROMIUM() override {
@@ -279,7 +287,8 @@ class GLES2InterfaceForTests : public gpu::gles2::GLES2InterfaceStub,
     state_.depth_mask = saved_state_.depth_mask;
     state_.stencil_mask = saved_state_.stencil_mask;
   }
-  void DrawingBufferClientRestorePixelPackAlignment() override {
+  void DrawingBufferClientRestorePixelPackParameters() override {
+    // TODO(zmo): restore ES3 pack parameters?
     state_.pack_alignment = saved_state_.pack_alignment;
   }
   void DrawingBufferClientRestoreTexture2DBinding() override {
@@ -296,6 +305,9 @@ class GLES2InterfaceForTests : public gpu::gles2::GLES2InterfaceStub,
     state_.pixel_unpack_buffer_binding =
         saved_state_.pixel_unpack_buffer_binding;
   }
+  void DrawingBufferClientRestorePixelPackBufferBinding() override {
+    state_.pixel_pack_buffer_binding = saved_state_.pixel_pack_buffer_binding;
+  }
 
   // Testing methods.
   gpu::SyncToken MostRecentlyWaitedSyncToken() const {
@@ -331,6 +343,8 @@ class GLES2InterfaceForTests : public gpu::gles2::GLES2InterfaceStub,
               saved_state_.read_framebuffer_binding);
     EXPECT_EQ(state_.pixel_unpack_buffer_binding,
               saved_state_.pixel_unpack_buffer_binding);
+    EXPECT_EQ(state_.pixel_pack_buffer_binding,
+              saved_state_.pixel_pack_buffer_binding);
   }
 
  private:
@@ -356,6 +370,7 @@ class GLES2InterfaceForTests : public gpu::gles2::GLES2InterfaceStub,
     GLuint draw_framebuffer_binding = 0;
     GLuint read_framebuffer_binding = 0;
     GLuint pixel_unpack_buffer_binding = 0;
+    GLuint pixel_pack_buffer_binding = 0;
   };
   State state_;
   State saved_state_;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
