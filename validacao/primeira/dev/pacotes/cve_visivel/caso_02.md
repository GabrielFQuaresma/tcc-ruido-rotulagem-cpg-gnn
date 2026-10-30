# Pacote de anotacao — caso 02

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

# Evidencia do caso 02

## Identificacao

- projeto: Chrome
- CVE: CVE-2012-5152
- CWE atribuida pelo BigVul: CWE-119
- commit: `802ecdb9cee0d66fe546bdf24e98150f8f716ad8`
- URL do commit: https://github.com/chromium/chromium/commit/802ecdb9cee0d66fe546bdf24e98150f8f716ad8
- arquivo da funcao marcada: `media/filters/audio_renderer_algorithm_unittest.cc`

## Mensagem do commit

> Protect AudioRendererAlgorithm from invalid step sizes.
> 
> BUG=165430
> TEST=unittests and asan pass.
> 
> Review URL: https://codereview.chromium.org/11573023
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@173249 0039d316-1c4b-4281-b951-d872f2087c98

## Resumo da CVE

> Google Chrome before 24.0.1312.52 allows remote attackers to cause a denial of service (out-of-bounds read) via vectors involving seek operations on video data.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -21,8 +21,8 @@
        int frames_requested = std::min(buffer_size_in_frames, frames_remaining);
        int frames_written =
            algorithm_.FillBuffer(buffer.get(), frames_requested);
-      CHECK_GT(frames_written, 0);
-      CheckFakeData(buffer.get(), frames_written, playback_rate);
+      ASSERT_GT(frames_written, 0);
+      CheckFakeData(buffer.get(), frames_written);
        frames_remaining -= frames_written;
      }
  
```

## Corpo completo da funcao antes da correcao

```c
  void TestPlaybackRate(double playback_rate,
                        int buffer_size_in_frames,
                        int total_frames_requested) {
    int initial_bytes_enqueued = bytes_enqueued_;
    int initial_bytes_buffered = algorithm_.bytes_buffered();

    algorithm_.SetPlaybackRate(static_cast<float>(playback_rate));

    scoped_array<uint8> buffer(
        new uint8[buffer_size_in_frames * algorithm_.bytes_per_frame()]);

    if (playback_rate == 0.0) {
      int frames_written =
          algorithm_.FillBuffer(buffer.get(), buffer_size_in_frames);
      EXPECT_EQ(0, frames_written);
      return;
    }

    int frames_remaining = total_frames_requested;
    while (frames_remaining > 0) {
       int frames_requested = std::min(buffer_size_in_frames, frames_remaining);
       int frames_written =
           algorithm_.FillBuffer(buffer.get(), frames_requested);
      CHECK_GT(frames_written, 0);
      CheckFakeData(buffer.get(), frames_written, playback_rate);
       frames_remaining -= frames_written;
     }
 
    int bytes_requested = total_frames_requested * algorithm_.bytes_per_frame();
    int bytes_consumed = ComputeConsumedBytes(initial_bytes_enqueued,
                                              initial_bytes_buffered);

    if (playback_rate == 1.0) {
      EXPECT_EQ(bytes_requested, bytes_consumed);
      return;
    }

    static const double kMaxAcceptableDelta = 0.01;
    double actual_playback_rate = 1.0 * bytes_consumed / bytes_requested;

    double delta = std::abs(1.0 - (actual_playback_rate / playback_rate));

    EXPECT_LE(delta, kMaxAcceptableDelta);
  }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `media/filters/audio_renderer_algorithm.cc` | modified | 23 | 17 |
| `media/filters/audio_renderer_algorithm.h` | modified | 4 | 2 |
| `media/filters/audio_renderer_algorithm_unittest.cc` **(funcao marcada esta aqui)** | modified | 42 | 61 |


### `media/filters/audio_renderer_algorithm_unittest.cc`

```diff
@@ -19,8 +19,8 @@
 
 namespace media {
 
-static const size_t kRawDataSize = 10 * 1024;
-static const int kSamplesPerSecond = 44100;
+static const size_t kRawDataSize = 2048;
+static const int kSamplesPerSecond = 3000;
 static const ChannelLayout kDefaultChannelLayout = CHANNEL_LAYOUT_STEREO;
 static const int kDefaultSampleBits = 16;
 
@@ -33,13 +33,16 @@ class AudioRendererAlgorithmTest : public testing::Test {
   ~AudioRendererAlgorithmTest() {}
 
   void Initialize() {
-    Initialize(kDefaultChannelLayout, kDefaultSampleBits);
+    Initialize(kDefaultChannelLayout, kDefaultSampleBits, kSamplesPerSecond);
   }
 
-  void Initialize(ChannelLayout channel_layout, int bits_per_channel) {
+  void Initialize(ChannelLayout channel_layout, int bits_per_channel,
+                  int samples_per_second) {
+    static const int kFrames = kRawDataSize / ((kDefaultSampleBits / 8) *
+        ChannelLayoutToChannelCount(kDefaultChannelLayout));
     AudioParameters params(
         media::AudioParameters::AUDIO_PCM_LINEAR, channel_layout,
-        kSamplesPerSecond, bits_per_channel, kRawDataSize);
+        samples_per_second, bits_per_channel, kFrames);
 
     algorithm_.Initialize(1, params, base::Bind(
         &AudioRendererAlgorithmTest::EnqueueData, base::Unretained(this)));
@@ -50,61 +53,22 @@ class AudioRendererAlgorithmTest : public testing::Test {
     scoped_array<uint8> audio_data(new uint8[kRawDataSize]);
     CHECK_EQ(kRawDataSize % algorithm_.bytes_per_channel(), 0u);
     CHECK_EQ(kRawDataSize % algorithm_.bytes_per_frame(), 0u);
-    size_t length = kRawDataSize / algorithm_.bytes_per_channel();
-    switch (algorithm_.bytes_per_channel()) {
-      case 4:
-        WriteFakeData<int32>(audio_data.get(), length);
-        break;
-      case 2:
-        WriteFakeData<int16>(audio_data.get(), length);
-        break;
-      case 1:
-        WriteFakeData<uint8>(audio_data.get(), length);
-        break;
-      default:
-        NOTREACHED() << "Unsupported audio bit depth in crossfade.";
-    }
+    // The value of the data is meaningless; we just want non-zero data to
+    // differentiate it from muted data.
+    memset(audio_data.get(), 1, kRawDataSize);
     algorithm_.EnqueueBuffer(new DataBuffer(audio_data.Pass(), kRawDataSize));
     bytes_enqueued_ += kRawDataSize;
   }
 
-  template <class Type>
-  void WriteFakeData(uint8* audio_data, size_t length) {
-    Type* output = reinterpret_cast<Type*>(audio_data);
-    for (size_t i = 0; i < length; i++) {
-      // The value of the data is meaningless; we just want non-zero data to
-      // differentiate it from muted data.
-      output[i] = i % 5 + 10;
-    }
-  }
+  void CheckFakeData(uint8* audio_data, int frames_written) {
+    int sum = 0;
+    for (int i = 0; i < frames_written * algorithm_.bytes_per_frame(); ++i)
+      sum |= audio_data[i];
 
-  void CheckFakeData(uint8* audio_data, int frames_written,
-                     double playback_rate) {
-    size_t length =
-        (frames_written * algorithm_.bytes_per_frame())
-        / algorithm_.bytes_per_channel();
-
-    switch (algorithm_.bytes_per_channel()) {
-      case 4:
-        DoCheckFakeData<int32>(audio_data, length);
-        break;
-      case 2:
-        DoCheckFakeData<int16>(audio_data, length);
-        break;
-      case 1:
-        DoCheckFakeData<uint8>(audio_data, length);
-        break;
-      default:
-        NOTREACHED() << "Unsupported audio bit depth in crossfade.";
-    }
-  }
-
-  template <class Type>
-  void DoCheckFakeData(uint8* audio_data, size_t length) {
-    Type* output = reinterpret_cast<Type*>(audio_data);
-    for (size_t i = 0; i < length; i++) {
-      EXPECT_TRUE(algorithm_.is_muted() || output[i] != 0);
-    }
+    if (algorithm_.is_muted())
+      ASSERT_EQ(sum, 0);
+    else
+      ASSERT_NE(sum, 0);
   }
 
   int ComputeConsumedBytes(int initial_bytes_enqueued,
@@ -117,8 +81,8 @@ class AudioRendererAlgorithmTest : public testing::Test {
   }
 
   void TestPlaybackRate(double playback_rate) {
-    static const int kDefaultBufferSize = kSamplesPerSecond / 10;
-    static const int kDefaultFramesRequested = 5 * kSamplesPerSecond;
+    const int kDefaultBufferSize = algorithm_.samples_per_second() / 10;
+    const int kDefaultFramesRequested = 2 * algorithm_.samples_per_second();
 
     TestPlaybackRate(playback_rate, kDefaultBufferSize,
                      kDefaultFramesRequested);
@@ -147,8 +111,8 @@ class AudioRendererAlgorithmTest : public testing::Test {
       int frames_requested = std::min(buffer_size_in_frames, frames_remaining);
       int frames_written =
           algorithm_.FillBuffer(buffer.get(), frames_requested);
-      CHECK_GT(frames_written, 0);
-      CheckFakeData(buffer.get(), frames_written, playback_rate);
+      ASSERT_GT(frames_written, 0);
+      CheckFakeData(buffer.get(), frames_written);
       frames_remaining -= frames_written;
     }
 
@@ -191,6 +155,16 @@ TEST_F(AudioRendererAlgorithmTest, FillBuffer_NormalRate) {
   TestPlaybackRate(1.0);
 }
 
+TEST_F(AudioRendererAlgorithmTest, FillBuffer_NearlyNormalFasterRate) {
+  Initialize();
+  TestPlaybackRate(1.0001);
+}
+
+TEST_F(AudioRendererAlgorithmTest, FillBuffer_NearlyNormalSlowerRate) {
+  Initialize();
+  TestPlaybackRate(0.9999);
+}
+
 TEST_F(AudioRendererAlgorithmTest, FillBuffer_OneAndAQuarterRate) {
   Initialize();
   TestPlaybackRate(1.25);
@@ -269,10 +243,17 @@ TEST_F(AudioRendererAlgorithmTest, FillBuffer_SmallBufferSize) {
   TestPlaybackRate(1.5, kBufferSizeInFrames, kFramesRequested);
 }
 
+TEST_F(AudioRendererAlgorithmTest, FillBuffer_LargeBufferSize) {
+  Initialize(kDefaultChannelLayout, kDefaultSampleBits, 44100);
+  TestPlaybackRate(1.0);
+  TestPlaybackRate(0.5);
+  TestPlaybackRate(1.5);
+}
+
 TEST_F(AudioRendererAlgorithmTest, FillBuffer_LowerQualityAudio) {
   static const ChannelLayout kChannelLayout = CHANNEL_LAYOUT_MONO;
   static const int kSampleBits = 8;
-  Initialize(kChannelLayout, kSampleBits);
+  Initialize(kChannelLayout, kSampleBits, kSamplesPerSecond);
   TestPlaybackRate(1.0);
   TestPlaybackRate(0.5);
   TestPlaybackRate(1.5);
@@ -281,7 +262,7 @@ TEST_F(AudioRendererAlgorithmTest, FillBuffer_LowerQualityAudio) {
 TEST_F(AudioRendererAlgorithmTest, FillBuffer_HigherQualityAudio) {
   static const ChannelLayout kChannelLayout = CHANNEL_LAYOUT_STEREO;
   static const int kSampleBits = 32;
-  Initialize(kChannelLayout, kSampleBits);
+  Initialize(kChannelLayout, kSampleBits, kSamplesPerSecond);
   TestPlaybackRate(1.0);
   TestPlaybackRate(0.5);
   TestPlaybackRate(1.5);
```


### `media/filters/audio_renderer_algorithm.cc`

```diff
@@ -83,19 +83,27 @@ int AudioRendererAlgorithm::FillBuffer(
   if (playback_rate_ == 0.0f)
     return 0;
 
+  int slower_step = ceil(window_size_ * playback_rate_);
+  int faster_step = ceil(window_size_ / playback_rate_);
+  AlignToFrameBoundary(&slower_step);
+  AlignToFrameBoundary(&faster_step);
+
   int total_frames_rendered = 0;
   uint8* output_ptr = dest;
   while (total_frames_rendered < requested_frames) {
     if (index_into_window_ == window_size_)
       ResetWindow();
 
     bool rendered_frame = true;
-    if (playback_rate_ > 1.0)
-      rendered_frame = OutputFasterPlayback(output_ptr);
-    else if (playback_rate_ < 1.0)
-      rendered_frame = OutputSlowerPlayback(output_ptr);
-    else
+    if (window_size_ > faster_step) {
+      rendered_frame = OutputFasterPlayback(
+          output_ptr, window_size_, faster_step);
+    } else if (slower_step < window_size_) {
+      rendered_frame = OutputSlowerPlayback(
+          output_ptr, slower_step, window_size_);
+    } else {
       rendered_frame = OutputNormalPlayback(output_ptr);
+    }
 
     if (!rendered_frame) {
       needs_more_data_ = true;
@@ -114,7 +122,11 @@ void AudioRendererAlgorithm::ResetWindow() {
   crossfade_frame_number_ = 0;
 }
 
-bool AudioRendererAlgorithm::OutputFasterPlayback(uint8* dest) {
+bool AudioRendererAlgorithm::OutputFasterPlayback(uint8* dest,
+                                                  int input_step,
+                                                  int output_step) {
+  // Ensure we don't run into OOB read/write situation.
+  CHECK_GT(input_step, output_step);
   DCHECK_LT(index_into_window_, window_size_);
   DCHECK_GT(playback_rate_, 1.0);
 
@@ -131,11 +143,6 @@ bool AudioRendererAlgorithm::OutputFasterPlayback(uint8* dest) {
   //
   // The duration of each phase is computed below based on the |window_size_|
   // and |playback_rate_|.
-  int input_step = window_size_;
-  int output_step = ceil(window_size_ / playback_rate_);
-  AlignToFrameBoundary(&output_step);
-  DCHECK_GT(input_step, output_step);
-
   int bytes_to_crossfade = bytes_in_crossfade_;
   if (muted_ || bytes_to_crossfade > output_step)
     bytes_to_crossfade = 0;
@@ -203,7 +210,11 @@ bool AudioRendererAlgorithm::OutputFasterPlayback(uint8* dest) {
   return true;
 }
 
-bool AudioRendererAlgorithm::OutputSlowerPlayback(uint8* dest) {
+bool AudioRendererAlgorithm::OutputSlowerPlayback(uint8* dest,
+                                                  int input_step,
+                                                  int output_step) {
+  // Ensure we don't run into OOB read/write situation.
+  CHECK_LT(input_step, output_step);
   DCHECK_LT(index_into_window_, window_size_);
   DCHECK_LT(playback_rate_, 1.0);
   DCHECK_NE(playback_rate_, 0.0);
@@ -224,11 +235,6 @@ bool AudioRendererAlgorithm::OutputSlowerPlayback(uint8* dest) {
   //
   // The duration of each phase is computed below based on the |window_size_|
   // and |playback_rate_|.
-  int input_step = ceil(window_size_ * playback_rate_);
-  AlignToFrameBoundary(&input_step);
-  int output_step = window_size_;
-  DCHECK_LT(input_step, output_step);
-
   int bytes_to_crossfade = bytes_in_crossfade_;
   if (muted_ || bytes_to_crossfade > input_step)
     bytes_to_crossfade = 0;
```


### `media/filters/audio_renderer_algorithm.h`

```diff
@@ -88,6 +88,8 @@ class MEDIA_EXPORT AudioRendererAlgorithm {
 
   int bytes_per_channel() { return bytes_per_channel_; }
 
+  int samples_per_second() { return samples_per_second_; }
+
   bool is_muted() { return muted_; }
 
  private:
@@ -103,7 +105,7 @@ class MEDIA_EXPORT AudioRendererAlgorithm {
   // data at normal speed, then we "fast forward" by dropping the next bit of
   // audio data, and then we stich the pieces together by crossfading from one
   // audio chunk to the next.
-  bool OutputFasterPlayback(uint8* dest);
+  bool OutputFasterPlayback(uint8* dest, int input_step, int output_step);
 
   // Fills |dest| with one frame of audio data at slower than normal speed.
   // Returns true if a frame was rendered, false otherwise.
@@ -114,7 +116,7 @@ class MEDIA_EXPORT AudioRendererAlgorithm {
   // by repeating some of the audio data from the previous audio segment.
   // Segments are stiched together by crossfading from one audio chunk to the
   // next.
-  bool OutputSlowerPlayback(uint8* dest);
+  bool OutputSlowerPlayback(uint8* dest, int input_step, int output_step);
 
   // Resets the window state to the start of a new window.
   void ResetWindow();
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
