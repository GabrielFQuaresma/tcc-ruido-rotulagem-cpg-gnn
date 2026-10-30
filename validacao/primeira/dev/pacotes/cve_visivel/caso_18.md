# Pacote de anotacao — caso 18

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

# Evidencia do caso 18

## Identificacao

- projeto: Android
- CVE: CVE-2016-1621
- CWE atribuida pelo BigVul: CWE-119
- commit: `04839626ed859623901ebd3a5fd483982186b59d`
- URL do commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- arquivo da funcao marcada: `libwebm/mkvparser.cpp`

## Mensagem do commit

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

## Resumo da CVE

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,16 +1 @@
 Cluster::Cluster(
-    Segment* pSegment,
-    long idx,
-    long long element_start
-    /* long long element_size */ ) :
-    m_pSegment(pSegment),
-    m_element_start(element_start),
-    m_index(idx),
-    m_pos(element_start),
-    m_element_size(-1 /* element_size */ ),
-    m_timecode(-1),
-    m_entries(NULL),
-    m_entries_size(0),
-    m_entries_count(-1)  //means "has not been parsed yet"
-{
-}
```

## Corpo completo da funcao antes da correcao

```c
Cluster::Cluster(
    Segment* pSegment,
    long idx,
    long long element_start
    /* long long element_size */ ) :
    m_pSegment(pSegment),
    m_element_start(element_start),
    m_index(idx),
    m_pos(element_start),
    m_element_size(-1 /* element_size */ ),
    m_timecode(-1),
    m_entries(NULL),
    m_entries_size(0),
    m_entries_count(-1)  //means "has not been parsed yet"
{
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **2**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `libwebm/mkvparser.cpp` **(funcao marcada esta aqui)** |  |  |  |
| `libwebm/mkvparser.hpp` |  |  |  |


### `libwebm/mkvparser.cpp`

```diff
@@ -12,1380 +12,1208 @@

 #include <new>
 #include <climits>
 
-mkvparser::IMkvReader::~IMkvReader()
-{
+#ifdef _MSC_VER
+// Disable MSVC warnings that suggest making code non-portable.
+#pragma warning(disable : 4996)
+#endif
+
+mkvparser::IMkvReader::~IMkvReader() {}
+
+void mkvparser::GetVersion(int& major, int& minor, int& build, int& revision) {
+  major = 1;
+  minor = 0;
+  build = 0;
+  revision = 28;
 }
 
-void mkvparser::GetVersion(int& major, int& minor, int& build, int& revision)
-{
-    major = 1;
-    minor = 0;
-    build = 0;
-    revision = 27;
-}
+long long mkvparser::ReadUInt(IMkvReader* pReader, long long pos, long& len) {
+  assert(pReader);
+  assert(pos >= 0);
 
-long long mkvparser::ReadUInt(IMkvReader* pReader, long long pos, long& len)
-{
-    assert(pReader);
-    assert(pos >= 0);
+  int status;
 
-    int status;
+  //#ifdef _DEBUG
+  //    long long total, available;
+  //    status = pReader->Length(&total, &available);
+  //    assert(status >= 0);
+  //    assert((total < 0) || (available <= total));
+  //    assert(pos < available);
+  //    assert((available - pos) >= 1);  //assume here max u-int len is 8
+  //#endif
 
-//#ifdef _DEBUG
-//    long long total, available;
-//    status = pReader->Length(&total, &available);
-//    assert(status >= 0);
-//    assert((total < 0) || (available <= total));
-//    assert(pos < available);
-//    assert((available - pos) >= 1);  //assume here max u-int len is 8
-//#endif
+  len = 1;
 
-    len = 1;
+  unsigned char b;
 
-    unsigned char b;
+  status = pReader->Read(pos, 1, &b);
 
+  if (status < 0)  // error or underflow
+    return status;
+
+  if (status > 0)  // interpreted as "underflow"
+    return E_BUFFER_NOT_FULL;
+
+  if (b == 0)  // we can't handle u-int values larger than 8 bytes
+    return E_FILE_FORMAT_INVALID;
+
+  unsigned char m = 0x80;
+
+  while (!(b & m)) {
+    m >>= 1;
+    ++len;
+  }
+
+  //#ifdef _DEBUG
+  //    assert((available - pos) >= len);
+  //#endif
+
+  long long result = b & (~m);
+  ++pos;
+
+  for (int i = 1; i < len; ++i) {
     status = pReader->Read(pos, 1, &b);
 
-    if (status < 0)  //error or underflow
-        return status;
-
-    if (status > 0)  //interpreted as "underflow"
-        return E_BUFFER_NOT_FULL;
-
-    if (b == 0)  //we can't handle u-int values larger than 8 bytes
-        return E_FILE_FORMAT_INVALID;
-
-    unsigned char m = 0x80;
-
-    while (!(b & m))
-    {
-        m >>= 1;
-        ++len;
+    if (status < 0) {
+      len = 1;
+      return status;
     }
 
-//#ifdef _DEBUG
-//    assert((available - pos) >= len);
-//#endif
+    if (status > 0) {
+      len = 1;
+      return E_BUFFER_NOT_FULL;
+    }
 
-    long long result = b & (~m);
+    result <<= 8;
+    result |= b;
+
     ++pos;
+  }
 
-    for (int i = 1; i < len; ++i)
-    {
-        status = pReader->Read(pos, 1, &b);
-
-        if (status < 0)
-        {
-            len = 1;
-            return status;
-        }
-
-        if (status > 0)
-        {
-            len = 1;
-            return E_BUFFER_NOT_FULL;
-        }
-
-        result <<= 8;
-        result |= b;
-
-        ++pos;
-    }
-
-    return result;
+  return result;
 }
 
-long long mkvparser::GetUIntLength(
-    IMkvReader* pReader,
-    long long pos,
-    long& len)
-{
-    assert(pReader);
-    assert(pos >= 0);
+long long mkvparser::GetUIntLength(IMkvReader* pReader, long long pos,
+                                   long& len) {
+  assert(pReader);
+  assert(pos >= 0);
 
-    long long total, available;
+  long long total, available;
 
-    int status = pReader->Length(&total, &available);
-    assert(status >= 0);
-    assert((total < 0) || (available <= total));
+  int status = pReader->Length(&total, &available);
+  assert(status >= 0);
+  assert((total < 0) || (available <= total));
 
-    len = 1;
+  len = 1;
 
-    if (pos >= available)
-        return pos;  //too few bytes available
+  if (pos >= available)
+    return pos;  // too few bytes available
 
+  unsigned char b;
+
+  status = pReader->Read(pos, 1, &b);
+
+  if (status < 0)
+    return status;
+
+  assert(status == 0);
+
+  if (b == 0)  // we can't handle u-int values larger than 8 bytes
+    return E_FILE_FORMAT_INVALID;
+
+  unsigned char m = 0x80;
+
+  while (!(b & m)) {
+    m >>= 1;
+    ++len;
+  }
+
+  return 0;  // success
+}
+
+// TODO(vigneshv): This function assumes that unsigned values never have their
+// high bit set.
+long long mkvparser::UnserializeUInt(IMkvReader* pReader, long long pos,
+                                     long long size) {
+  assert(pReader);
+  assert(pos >= 0);
+
+  if ((size <= 0) || (size > 8))
+    return E_FILE_FORMAT_INVALID;
+
+  long long result = 0;
+
+  for (long long i = 0; i < size; ++i) {
     unsigned char b;
 
-    status = pReader->Read(pos, 1, &b);
+    const long status = pReader->Read(pos, 1, &b);
 
     if (status < 0)
-        return status;
+      return status;
 
-    assert(status == 0);
+    result <<= 8;
+    result |= b;
 
-    if (b == 0)  //we can't handle u-int values larger than 8 bytes
-        return E_FILE_FORMAT_INVALID;
+    ++pos;
+  }
 
-    unsigned char m = 0x80;
-
-    while (!(b & m))
-    {
-        m >>= 1;
-        ++len;
-    }
-
-    return 0;  //success
+  return result;
 }
 
+long mkvparser::UnserializeFloat(IMkvReader* pReader, long long pos,
+                                 long long size_, double& result) {
+  assert(pReader);
+  assert(pos >= 0);
 
-long long mkvparser::UnserializeUInt(
-    IMkvReader* pReader,
-    long long pos,
-    long long size)
-{
-    assert(pReader);
-    assert(pos >= 0);
+  if ((size_ != 4) && (size_ != 8))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((size <= 0) || (size > 8))
-        return E_FILE_FORMAT_INVALID;
+  const long size = static_cast<long>(size_);
 
-    long long result = 0;
+  unsigned char buf[8];
 
-    for (long long i = 0; i < size; ++i)
-    {
-        unsigned char b;
+  const int status = pReader->Read(pos, size, buf);
 
-        const long status = pReader->Read(pos, 1, &b);
+  if (status < 0)  // error
+    return status;
 
-        if (status < 0)
-            return status;
+  if (size == 4) {
+    union {
+      float f;
+      unsigned long ff;
+    };
 
-        result <<= 8;
-        result |= b;
+    ff = 0;
 
-        ++pos;
+    for (int i = 0;;) {
+      ff |= buf[i];
+
+      if (++i >= 4)
+        break;
+
+      ff <<= 8;
     }
 
-    return result;
+    result = f;
+  } else {
+    assert(size == 8);
+
+    union {
+      double d;
+      unsigned long long dd;
+    };
+
+    dd = 0;
+
+    for (int i = 0;;) {
+      dd |= buf[i];
+
+      if (++i >= 8)
+        break;
+
+      dd <<= 8;
+    }
+
+    result = d;
+  }
+
+  return 0;
 }
 
+long mkvparser::UnserializeInt(IMkvReader* pReader, long long pos, long size,
+                               long long& result) {
+  assert(pReader);
+  assert(pos >= 0);
+  assert(size > 0);
+  assert(size <= 8);
 
-long mkvparser::UnserializeFloat(
-    IMkvReader* pReader,
-    long long pos,
-    long long size_,
-    double& result)
-{
-    assert(pReader);
-    assert(pos >= 0);
+  {
+    signed char b;
 
-    if ((size_ != 4) && (size_ != 8))
-        return E_FILE_FORMAT_INVALID;
+    const long status = pReader->Read(pos, 1, (unsigned char*)&b);
 
-    const long size = static_cast<long>(size_);
+    if (status < 0)
+      return status;
 
-    unsigned char buf[8];
+    result = b;
 
-    const int status = pReader->Read(pos, size, buf);
+    ++pos;
+  }
 
-    if (status < 0)  //error
-        return status;
+  for (long i = 1; i < size; ++i) {
+    unsigned char b;
 
-    if (size == 4)
-    {
-        union
-        {
-            float f;
-            unsigned long ff;
-        };
+    const long status = pReader->Read(pos, 1, &b);
 
-        ff = 0;
+    if (status < 0)
+      return status;
 
-        for (int i = 0;;)
-        {
-            ff |= buf[i];
+    result <<= 8;
+    result |= b;
 
-            if (++i >= 4)
-                break;
+    ++pos;
+  }
 
-            ff <<= 8;
-        }
-
-        result = f;
-    }
-    else
-    {
-        assert(size == 8);
-
-        union
-        {
-            double d;
-            unsigned long long dd;
-        };
-
-        dd = 0;
-
-        for (int i = 0;;)
-        {
-            dd |= buf[i];
-
-            if (++i >= 8)
-                break;
-
-            dd <<= 8;
-        }
-
-        result = d;
-    }
-
-    return 0;
+  return 0;  // success
 }
 
+long mkvparser::UnserializeString(IMkvReader* pReader, long long pos,
+                                  long long size_, char*& str) {
+  delete[] str;
+  str = NULL;
 
-long mkvparser::UnserializeInt(
-    IMkvReader* pReader,
-    long long pos,
-    long size,
-    long long& result)
-{
-    assert(pReader);
-    assert(pos >= 0);
-    assert(size > 0);
-    assert(size <= 8);
+  if (size_ >= LONG_MAX)  // we need (size+1) chars
+    return E_FILE_FORMAT_INVALID;
 
-    {
-        signed char b;
+  const long size = static_cast<long>(size_);
 
-        const long status = pReader->Read(pos, 1, (unsigned char*)&b);
+  str = new (std::nothrow) char[size + 1];
 
-        if (status < 0)
-            return status;
+  if (str == NULL)
+    return -1;
 
-        result = b;
+  unsigned char* const buf = reinterpret_cast<unsigned char*>(str);
 
-        ++pos;
-    }
+  const long status = pReader->Read(pos, size, buf);
 
-    for (long i = 1; i < size; ++i)
-    {
-        unsigned char b;
-
-        const long status = pReader->Read(pos, 1, &b);
-
-        if (status < 0)
-            return status;
-
-        result <<= 8;
-        result |= b;
-
-        ++pos;
-    }
-
-    return 0;  //success
-}
-
-
-long mkvparser::UnserializeString(
-    IMkvReader* pReader,
-    long long pos,
-    long long size_,
-    char*& str)
-{
+  if (status) {
     delete[] str;
     str = NULL;
 
-    if (size_ >= LONG_MAX)  //we need (size+1) chars
-        return E_FILE_FORMAT_INVALID;
+    return status;
+  }
 
-    const long size = static_cast<long>(size_);
+  str[size] = '\0';
 
-    str = new (std::nothrow) char[size+1];
-
-    if (str == NULL)
-        return -1;
-
-    unsigned char* const buf = reinterpret_cast<unsigned char*>(str);
-
-    const long status = pReader->Read(pos, size, buf);
-
-    if (status)
-    {
-        delete[] str;
-        str = NULL;
-
-        return status;
-    }
-
-    str[size] = '\0';
-
-    return 0;  //success
+  return 0;  // success
 }
 
+long mkvparser::ParseElementHeader(IMkvReader* pReader, long long& pos,
+                                   long long stop, long long& id,
+                                   long long& size) {
+  if ((stop >= 0) && (pos >= stop))
+    return E_FILE_FORMAT_INVALID;
 
-long mkvparser::ParseElementHeader(
-    IMkvReader* pReader,
-    long long& pos,
-    long long stop,
-    long long& id,
-    long long& size)
-{
-    if ((stop >= 0) && (pos >= stop))
-        return E_FILE_FORMAT_INVALID;
+  long len;
 
-    long len;
+  id = ReadUInt(pReader, pos, len);
 
-    id = ReadUInt(pReader, pos, len);
+  if (id < 0)
+    return E_FILE_FORMAT_INVALID;
 
-    if (id < 0)
-        return E_FILE_FORMAT_INVALID;
+  pos += len;  // consume id
 
-    pos += len;  //consume id
+  if ((stop >= 0) && (pos >= stop))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((stop >= 0) && (pos >= stop))
-        return E_FILE_FORMAT_INVALID;
+  size = ReadUInt(pReader, pos, len);
 
-    size = ReadUInt(pReader, pos, len);
+  if (size < 0)
+    return E_FILE_FORMAT_INVALID;
 
-    if (size < 0)
-        return E_FILE_FORMAT_INVALID;
+  pos += len;  // consume length of size
 
-    pos += len;  //consume length of size
+  // pos now designates payload
 
-    //pos now designates payload
+  if ((stop >= 0) && ((pos + size) > stop))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((stop >= 0) && ((pos + size) > stop))
-        return E_FILE_FORMAT_INVALID;
-
-    return 0;  //success
+  return 0;  // success
 }
 
+bool mkvparser::Match(IMkvReader* pReader, long long& pos, unsigned long id_,
+                      long long& val) {
+  assert(pReader);
+  assert(pos >= 0);
 
-bool mkvparser::Match(
-    IMkvReader* pReader,
-    long long& pos,
-    unsigned long id_,
-    long long& val)
-{
-    assert(pReader);
-    assert(pos >= 0);
+  long long total, available;
 
-    long long total, available;
+  const long status = pReader->Length(&total, &available);
+  assert(status >= 0);
+  assert((total < 0) || (available <= total));
+  if (status < 0)
+    return false;
 
-    const long status = pReader->Length(&total, &available);
-    assert(status >= 0);
-    assert((total < 0) || (available <= total));
-    if (status < 0)
-        return false;
+  long len;
 
-    long len;
+  const long long id = ReadUInt(pReader, pos, len);
+  assert(id >= 0);
+  assert(len > 0);
+  assert(len <= 8);
+  assert((pos + len) <= available);
 
-    const long long id = ReadUInt(pReader, pos, len);
-    assert(id >= 0);
-    assert(len > 0);
-    assert(len <= 8);
-    assert((pos + len) <= available);
+  if ((unsigned long)id != id_)
+    return false;
 
-    if ((unsigned long)id != id_)
-        return false;
+  pos += len;  // consume id
 
-    pos += len;  //consume id
+  const long long size = ReadUInt(pReader, pos, len);
+  assert(size >= 0);
+  assert(size <= 8);
+  assert(len > 0);
+  assert(len <= 8);
+  assert((pos + len) <= available);
 
-    const long long size = ReadUInt(pReader, pos, len);
-    assert(size >= 0);
-    assert(size <= 8);
-    assert(len > 0);
-    assert(len <= 8);
-    assert((pos + len) <= available);
+  pos += len;  // consume length of size of payload
 
-    pos += len;  //consume length of size of payload
+  val = UnserializeUInt(pReader, pos, size);
+  assert(val >= 0);
 
-    val = UnserializeUInt(pReader, pos, size);
-    assert(val >= 0);
+  pos += size;  // consume size of payload
 
-    pos += size;  //consume size of payload
-
-    return true;
+  return true;
 }
 
-bool mkvparser::Match(
-    IMkvReader* pReader,
-    long long& pos,
-    unsigned long id_,
-    unsigned char*& buf,
-    size_t& buflen)
-{
-    assert(pReader);
-    assert(pos >= 0);
+bool mkvparser::Match(IMkvReader* pReader, long long& pos, unsigned long id_,
+                      unsigned char*& buf, size_t& buflen) {
+  assert(pReader);
+  assert(pos >= 0);
 
-    long long total, available;
+  long long total, available;
 
-    long status = pReader->Length(&total, &available);
-    assert(status >= 0);
-    assert((total < 0) || (available <= total));
-    if (status < 0)
-        return false;
+  long status = pReader->Length(&total, &available);
+  assert(status >= 0);
+  assert((total < 0) || (available <= total));
+  if (status < 0)
+    return false;
 
-    long len;
-    const long long id = ReadUInt(pReader, pos, len);
-    assert(id >= 0);
-    assert(len > 0);
-    assert(len <= 8);
-    assert((pos + len) <= available);
+  long len;
+  const long long id = ReadUInt(pReader, pos, len);
+  assert(id >= 0);
+  assert(len > 0);
+  assert(len <= 8);
+  assert((pos + len) <= available);
 
-    if ((unsigned long)id != id_)
-        return false;
+  if ((unsigned long)id != id_)
+    return false;
 
-    pos += len;  //consume id
+  pos += len;  // consume id
 
-    const long long size_ = ReadUInt(pReader, pos, len);
-    assert(size_ >= 0);
-    assert(len > 0);
-    assert(len <= 8);
-    assert((pos + len) <= available);
+  const long long size_ = ReadUInt(pReader, pos, len);
+  assert(size_ >= 0);
+  assert(len > 0);
+  assert(len <= 8);
+  assert((pos + len) <= available);
 
-    pos += len;  //consume length of size of payload
-    assert((pos + size_) <= available);
+  pos += len;  // consume length of size of payload
+  assert((pos + size_) <= available);
 
-    const long buflen_ = static_cast<long>(size_);
+  const long buflen_ = static_cast<long>(size_);
 
-    buf = new (std::nothrow) unsigned char[buflen_];
-    assert(buf);  //TODO
+  buf = new (std::nothrow) unsigned char[buflen_];
+  assert(buf);  // TODO
 
-    status = pReader->Read(pos, buflen_, buf);
-    assert(status == 0);  //TODO
+  status = pReader->Read(pos, buflen_, buf);
+  assert(status == 0);  // TODO
 
-    buflen = buflen_;
+  buflen = buflen_;
 
-    pos += size_;  //consume size of payload
-    return true;
+  pos += size_;  // consume size of payload
+  return true;
 }
 
+namespace mkvparser {
 
-namespace mkvparser
-{
+EBMLHeader::EBMLHeader() : m_docType(NULL) { Init(); }
 
-EBMLHeader::EBMLHeader() :
-    m_docType(NULL)
-{
-    Init();
-}
+EBMLHeader::~EBMLHeader() { delete[] m_docType; }
 
-EBMLHeader::~EBMLHeader()
-{
+void EBMLHeader::Init() {
+  m_version = 1;
+  m_readVersion = 1;
+  m_maxIdLength = 4;
+  m_maxSizeLength = 8;
+
+  if (m_docType) {
     delete[] m_docType;
+    m_docType = NULL;
+  }
+
+  m_docTypeVersion = 1;
+  m_docTypeReadVersion = 1;
 }
 
-void EBMLHeader::Init()
-{
-    m_version = 1;
-    m_readVersion = 1;
-    m_maxIdLength = 4;
-    m_maxSizeLength = 8;
+long long EBMLHeader::Parse(IMkvReader* pReader, long long& pos) {
+  assert(pReader);
 
-    if (m_docType)
-    {
-        delete[] m_docType;
-        m_docType = NULL;
-    }
+  long long total, available;
 
-    m_docTypeVersion = 1;
-    m_docTypeReadVersion = 1;
-}
+  long status = pReader->Length(&total, &available);
 
-long long EBMLHeader::Parse(
-    IMkvReader* pReader,
-    long long& pos)
-{
-    assert(pReader);
+  if (status < 0)  // error
+    return status;
 
-    long long total, available;
+  pos = 0;
+  long long end = (available >= 1024) ? 1024 : available;
 
-    long status = pReader->Length(&total, &available);
+  for (;;) {
+    unsigned char b = 0;
 
-    if (status < 0)  //error
+    while (pos < end) {
+      status = pReader->Read(pos, 1, &b);
+
+      if (status < 0)  // error
         return status;
 
-    pos = 0;
-    long long end = (available >= 1024) ? 1024 : available;
+      if (b == 0x1A)
+        break;
 
-    for (;;)
-    {
-        unsigned char b = 0;
-
-        while (pos < end)
-        {
-            status = pReader->Read(pos, 1, &b);
-
-            if (status < 0)  //error
-                return status;
-
-            if (b == 0x1A)
-                break;
-
-            ++pos;
-        }
-
-        if (b != 0x1A)
-        {
-            if (pos >= 1024)
-                return E_FILE_FORMAT_INVALID;  //don't bother looking anymore
-
-            if ((total >= 0) && ((total - available) < 5))
-                return E_FILE_FORMAT_INVALID;
-
-            return available + 5;  //5 = 4-byte ID + 1st byte of size
-        }
-
-        if ((total >= 0) && ((total - pos) < 5))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((available - pos) < 5)
-            return pos + 5;  //try again later
-
-        long len;
-
-        const long long result = ReadUInt(pReader, pos, len);
-
-        if (result < 0)  //error
-            return result;
-
-        if (result == 0x0A45DFA3)  //EBML Header ID
-        {
-            pos += len;  //consume ID
-            break;
-        }
-
-        ++pos;  //throw away just the 0x1A byte, and try again
+      ++pos;
     }
 
-    //pos designates start of size field
+    if (b != 0x1A) {
+      if (pos >= 1024)
+        return E_FILE_FORMAT_INVALID;  // don't bother looking anymore
 
-    //get length of size field
+      if ((total >= 0) && ((total - available) < 5))
+        return E_FILE_FORMAT_INVALID;
 
+      return available + 5;  // 5 = 4-byte ID + 1st byte of size
+    }
+
+    if ((total >= 0) && ((total - pos) < 5))
+      return E_FILE_FORMAT_INVALID;
+
+    if ((available - pos) < 5)
+      return pos + 5;  // try again later
+
+    long len;
+
+    const long long result = ReadUInt(pReader, pos, len);
+
+    if (result < 0)  // error
+      return result;
+
+    if (result == 0x0A45DFA3) {  // EBML Header ID
+      pos += len;  // consume ID
+      break;
+    }
+
+    ++pos;  // throw away just the 0x1A byte, and try again
+  }
+
+  // pos designates start of size field
+
+  // get length of size field
+
+  long len;
+  long long result = GetUIntLength(pReader, pos, len);
+
+  if (result < 0)  // error
+    return result;
+
+  if (result > 0)  // need more data
+    return result;
+
+  assert(len > 0);
+  assert(len <= 8);
+
+  if ((total >= 0) && ((total - pos) < len))
+    return E_FILE_FORMAT_INVALID;
+
+  if ((available - pos) < len)
+    return pos + len;  // try again later
+
+  // get the EBML header size
+
+  result = ReadUInt(pReader, pos, len);
+
+  if (result < 0)  // error
+    return result;
+
+  pos += len;  // consume size field
+
+  // pos now designates start of payload
+
+  if ((total >= 0) && ((total - pos) < result))
+    return E_FILE_FORMAT_INVALID;
+
+  if ((available - pos) < result)
+    return pos + result;
+
+  end = pos + result;
+
+  Init();
+
+  while (pos < end) {
+    long long id, size;
+
+    status = ParseElementHeader(pReader, pos, end, id, size);
+
+    if (status < 0)  // error
+      return status;
+
+    if (size == 0)  // weird
+      return E_FILE_FORMAT_INVALID;
+
+    if (id == 0x0286) {  // version
+      m_version = UnserializeUInt(pReader, pos, size);
+
+      if (m_version <= 0)
+        return E_FILE_FORMAT_INVALID;
+    } else if (id == 0x02F7) {  // read version
+      m_readVersion = UnserializeUInt(pReader, pos, size);
+
+      if (m_readVersion <= 0)
+        return E_FILE_FORMAT_INVALID;
+    } else if (id == 0x02F2) {  // max id length
+      m_maxIdLength = UnserializeUInt(pReader, pos, size);
+
+      if (m_maxIdLength <= 0)
+        return E_FILE_FORMAT_INVALID;
+    } else if (id == 0x02F3) {  // max size length
+      m_maxSizeLength = UnserializeUInt(pReader, pos, size);
+
+      if (m_maxSizeLength <= 0)
+        return E_FILE_FORMAT_INVALID;
+    } else if (id == 0x0282) {  // doctype
+      if (m_docType)
+        return E_FILE_FORMAT_INVALID;
+
+      status = UnserializeString(pReader, pos, size, m_docType);
+
+      if (status)  // error
+        return status;
+    } else if (id == 0x0287) {  // doctype version
+      m_docTypeVersion = UnserializeUInt(pReader, pos, size);
+
+      if (m_docTypeVersion <= 0)
+        return E_FILE_FORMAT_INVALID;
+    } else if (id == 0x0285) {  // doctype read version
+      m_docTypeReadVersion = UnserializeUInt(pReader, pos, size);
+
+      if (m_docTypeReadVersion <= 0)
+        return E_FILE_FORMAT_INVALID;
+    }
+
+    pos += size;
+  }
+
+  assert(pos == end);
+  return 0;
+}
+
+Segment::Segment(IMkvReader* pReader, long long elem_start,
+                 // long long elem_size,
+                 long long start, long long size)
+    : m_pReader(pReader),
+      m_element_start(elem_start),
+      // m_element_size(elem_size),
+      m_start(start),
+      m_size(size),
+      m_pos(start),
+      m_pUnknownSize(0),
+      m_pSeekHead(NULL),
+      m_pInfo(NULL),
+      m_pTracks(NULL),
+      m_pCues(NULL),
+      m_pChapters(NULL),
+      m_clusters(NULL),
+      m_clusterCount(0),
+      m_clusterPreloadCount(0),
+      m_clusterSize(0) {}
+
+Segment::~Segment() {
+  const long count = m_clusterCount + m_clusterPreloadCount;
+
+  Cluster** i = m_clusters;
+  Cluster** j = m_clusters + count;
+
+  while (i != j) {
+    Cluster* const p = *i++;
+    assert(p);
+
+    delete p;
+  }
+
+  delete[] m_clusters;
+
+  delete m_pTracks;
+  delete m_pInfo;
+  delete m_pCues;
+  delete m_pChapters;
+  delete m_pSeekHead;
+}
+
+long long Segment::CreateInstance(IMkvReader* pReader, long long pos,
+                                  Segment*& pSegment) {
+  assert(pReader);
+  assert(pos >= 0);
+
+  pSegment = NULL;
+
+  long long total, available;
+
+  const long status = pReader->Length(&total, &available);
+
+  if (status < 0)  // error
+    return status;
+
+  if (available < 0)
+    return -1;
+
+  if ((total >= 0) && (available > total))
+    return -1;
+
+  // I would assume that in practice this loop would execute
+  // exactly once, but we allow for other elements (e.g. Void)
+  // to immediately follow the EBML header.  This is fine for
+  // the source filter case (since the entire file is available),
+  // but in the splitter case over a network we should probably
+  // just give up early.  We could for example decide only to
+  // execute this loop a maximum of, say, 10 times.
+  // TODO:
+  // There is an implied "give up early" by only parsing up
+  // to the available limit.  We do do that, but only if the
+  // total file size is unknown.  We could decide to always
+  // use what's available as our limit (irrespective of whether
+  // we happen to know the total file length).  This would have
+  // as its sense "parse this much of the file before giving up",
+  // which a slightly different sense from "try to parse up to
+  // 10 EMBL elements before giving up".
+
+  for (;;) {
+    if ((total >= 0) && (pos >= total))
+      return E_FILE_FORMAT_INVALID;
+
+    // Read ID
     long len;
     long long result = GetUIntLength(pReader, pos, len);
 
-    if (result < 0)  //error
-        return result;
+    if (result)  // error, or too few available bytes
+      return result;
 
-    if (result > 0)  //need more data
-        return result;
+    if ((total >= 0) && ((pos + len) > total))
+      return E_FILE_FORMAT_INVALID;
 
-    assert(len > 0);
-    assert(len <= 8);
+    if ((pos + len) > available)
+      return pos + len;
 
-    if ((total >= 0) && ((total -  pos) < len))
-        return E_FILE_FORMAT_INVALID;
+    const long long idpos = pos;
+    const long long id = ReadUInt(pReader, pos, len);
 
-    if ((available - pos) < len)
-        return pos + len;  //try again later
+    if (id < 0)  // error
+      return id;
 
-    //get the EBML header size
+    pos += len;  // consume ID
 
-    result = ReadUInt(pReader, pos, len);
+    // Read Size
 
-    if (result < 0)  //error
-        return result;
+    result = GetUIntLength(pReader, pos, len);
 
-    pos += len;  //consume size field
+    if (result)  // error, or too few available bytes
+      return result;
 
-    //pos now designates start of payload
+    if ((total >= 0) && ((pos + len) > total))
+      return E_FILE_FORMAT_INVALID;
 
-    if ((total >= 0) && ((total - pos) < result))
-        return E_FILE_FORMAT_INVALID;
+    if ((pos + len) > available)
+      return pos + len;
 
-    if ((available - pos) < result)
-        return pos + result;
+    long long size = ReadUInt(pReader, pos, len);
 
-    end = pos + result;
+    if (size < 0)  // error
+      return size;
 
-    Init();
+    pos += len;  // consume length of size of element
 
-    while (pos < end)
-    {
-        long long id, size;
+    // Pos now points to start of payload
 
-        status = ParseElementHeader(
-                    pReader,
-                    pos,
-                    end,
-                    id,
-                    size);
+    // Handle "unknown size" for live streaming of webm files.
+    const long long unknown_size = (1LL << (7 * len)) - 1;
 
-        if (status < 0) //error
-            return status;
+    if (id == 0x08538067) {  // Segment ID
+      if (size == unknown_size)
+        size = -1;
 
-        if (size == 0)  //weird
-            return E_FILE_FORMAT_INVALID;
+      else if (total < 0)
+        size = -1;
 
-        if (id == 0x0286)  //version
-        {
-            m_version = UnserializeUInt(pReader, pos, size);
+      else if ((pos + size) > total)
+        size = -1;
 
-            if (m_version <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-        else if (id == 0x02F7)  //read version
-        {
-            m_readVersion = UnserializeUInt(pReader, pos, size);
+      pSegment = new (std::nothrow) Segment(pReader, idpos,
+                                            // elem_size
+                                            pos, size);
 
-            if (m_readVersion <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-        else if (id == 0x02F2)  //max id length
-        {
-            m_maxIdLength = UnserializeUInt(pReader, pos, size);
+      if (pSegment == 0)
+        return -1;  // generic error
 
-            if (m_maxIdLength <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-        else if (id == 0x02F3)  //max size length
-        {
-            m_maxSizeLength = UnserializeUInt(pReader, pos, size);
-
-            if (m_maxSizeLength <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-        else if (id == 0x0282)  //doctype
-        {
-            if (m_docType)
-                return E_FILE_FORMAT_INVALID;
-
-            status = UnserializeString(pReader, pos, size, m_docType);
-
-            if (status)  //error
-                return status;
-        }
-        else if (id == 0x0287)  //doctype version
-        {
-            m_docTypeVersion = UnserializeUInt(pReader, pos, size);
-
-            if (m_docTypeVersion <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-        else if (id == 0x0285)  //doctype read version
-        {
-            m_docTypeReadVersion = UnserializeUInt(pReader, pos, size);
-
-            if (m_docTypeReadVersion <= 0)
-                return E_FILE_FORMAT_INVALID;
-        }
-
-        pos += size;
+      return 0;  // success
     }
 
-    assert(pos == end);
-    return 0;
+    if (size == unknown_size)
+      return E_FILE_FORMAT_INVALID;
+
+    if ((total >= 0) && ((pos + size) > total))
+      return E_FILE_FORMAT_INVALID;
+
+    if ((pos + size) > available)
+      return pos + size;
+
+    pos += size;  // consume payload
+  }
 }
 
+long long Segment::ParseHeaders() {
+  // Outermost (level 0) segment object has been constructed,
+  // and pos designates start of payload.  We need to find the
+  // inner (level 1) elements.
+  long long total, available;
 
-Segment::Segment(
-    IMkvReader* pReader,
-    long long elem_start,
-    //long long elem_size,
-    long long start,
-    long long size) :
-    m_pReader(pReader),
-    m_element_start(elem_start),
-    //m_element_size(elem_size),
-    m_start(start),
-    m_size(size),
-    m_pos(start),
-    m_pUnknownSize(0),
-    m_pSeekHead(NULL),
-    m_pInfo(NULL),
-    m_pTracks(NULL),
-    m_pCues(NULL),
-    m_pChapters(NULL),
-    m_clusters(NULL),
-    m_clusterCount(0),
-    m_clusterPreloadCount(0),
-    m_clusterSize(0)
-{
-}
+  const int status = m_pReader->Length(&total, &available);
 
+  if (status < 0)  // error
+    return status;
 
-Segment::~Segment()
-{
-    const long count = m_clusterCount + m_clusterPreloadCount;
+  assert((total < 0) || (available <= total));
 
-    Cluster** i = m_clusters;
-    Cluster** j = m_clusters + count;
+  const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
+  assert((segment_stop < 0) || (total < 0) || (segment_stop <= total));
+  assert((segment_stop < 0) || (m_pos <= segment_stop));
 
-    while (i != j)
-    {
-        Cluster* const p = *i++;
-        assert(p);
+  for (;;) {
+    if ((total >= 0) && (m_pos >= total))
+      break;
 
-        delete p;
-    }
+    if ((segment_stop >= 0) && (m_pos >= segment_stop))
+      break;
 
-    delete[] m_clusters;
+    long long pos = m_pos;
+    const long long element_start = pos;
 
-    delete m_pTracks;
-    delete m_pInfo;
-    delete m_pCues;
-    delete m_pChapters;
-    delete m_pSeekHead;
-}
+    if ((pos + 1) > available)
+      return (pos + 1);
 
+    long len;
+    long long result = GetUIntLength(m_pReader, pos, len);
 
-long long Segment::CreateInstance(
-    IMkvReader* pReader,
-    long long pos,
-    Segment*& pSegment)
-{
-    assert(pReader);
-    assert(pos >= 0);
+    if (result < 0)  // error
+      return result;
 
-    pSegment = NULL;
+    if (result > 0)  // underflow (weird)
+      return (pos + 1);
 
-    long long total, available;
+    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+      return E_FILE_FORMAT_INVALID;
 
-    const long status = pReader->Length(&total, &available);
+    if ((pos + len) > available)
+      return pos + len;
 
-    if (status < 0) //error
-        return status;
+    const long long idpos = pos;
+    const long long id = ReadUInt(m_pReader, idpos, len);
 
-    if (available < 0)
+    if (id < 0)  // error
+      return id;
+
+    if (id == 0x0F43B675)  // Cluster ID
+      break;
+
+    pos += len;  // consume ID
+
+    if ((pos + 1) > available)
+      return (pos + 1);
+
+    // Read Size
+    result = GetUIntLength(m_pReader, pos, len);
+
+    if (result < 0)  // error
+      return result;
+
+    if (result > 0)  // underflow (weird)
+      return (pos + 1);
+
+    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+      return E_FILE_FORMAT_INVALID;
+
+    if ((pos + len) > available)
+      return pos + len;
+
+    const long long size = ReadUInt(m_pReader, pos, len);
+
+    if (size < 0)  // error
+      return size;
+
+    pos += len;  // consume length of size of element
+
+    const long long element_size = size + pos - element_start;
+
+    // Pos now points to start of payload
+
+    if ((segment_stop >= 0) && ((pos + size) > segment_stop))
+      return E_FILE_FORMAT_INVALID;
+
+    // We read EBML elements either in total or nothing at all.
+
+    if ((pos + size) > available)
+      return pos + size;
+
+    if (id == 0x0549A966) {  // Segment Info ID
+      if (m_pInfo)
+        return E_FILE_FORMAT_INVALID;
+
+      m_pInfo = new (std::nothrow)
+          SegmentInfo(this, pos, size, element_start, element_size);
+
+      if (m_pInfo == NULL)
         return -1;
 
-    if ((total >= 0) && (available > total))
+      const long status = m_pInfo->Parse();
+
+      if (status)
+        return status;
+    } else if (id == 0x0654AE6B) {  // Tracks ID
+      if (m_pTracks)
+        return E_FILE_FORMAT_INVALID;
+
+      m_pTracks = new (std::nothrow)
+          Tracks(this, pos, size, element_start, element_size);
+
+      if (m_pTracks == NULL)
         return -1;
 
-    //I would assume that in practice this loop would execute
-    //exactly once, but we allow for other elements (e.g. Void)
-    //to immediately follow the EBML header.  This is fine for
-    //the source filter case (since the entire file is available),
-    //but in the splitter case over a network we should probably
-    //just give up early.  We could for example decide only to
-    //execute this loop a maximum of, say, 10 times.
-    //TODO:
-    //There is an implied "give up early" by only parsing up
-    //to the available limit.  We do do that, but only if the
-    //total file size is unknown.  We could decide to always
-    //use what's available as our limit (irrespective of whether
-    //we happen to know the total file length).  This would have
-    //as its sense "parse this much of the file before giving up",
-    //which a slightly different sense from "try to parse up to
-    //10 EMBL elements before giving up".
+      const long status = m_pTracks->Parse();
 
-    for (;;)
-    {
-        if ((total >= 0) && (pos >= total))
-            return E_FILE_FORMAT_INVALID;
-
-        //Read ID
-        long len;
-        long long result = GetUIntLength(pReader, pos, len);
-
-        if (result)  //error, or too few available bytes
-            return result;
-
-        if ((total >= 0) && ((pos + len) > total))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + len) > available)
-            return pos + len;
-
-        const long long idpos = pos;
-        const long long id = ReadUInt(pReader, pos, len);
-
-        if (id < 0)  //error
-            return id;
-
-        pos += len;  //consume ID
-
-        //Read Size
-
-        result = GetUIntLength(pReader, pos, len);
-
-        if (result)  //error, or too few available bytes
-            return result;
-
-        if ((total >= 0) && ((pos + len) > total))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + len) > available)
-            return pos + len;
-
-        long long size = ReadUInt(pReader, pos, len);
-
-        if (size < 0)  //error
-            return size;
-
-        pos += len;  //consume length of size of element
-
-        //Pos now points to start of payload
-
-        //Handle "unknown size" for live streaming of webm files.
-        const long long unknown_size = (1LL << (7 * len)) - 1;
-
-        if (id == 0x08538067)  //Segment ID
-        {
-            if (size == unknown_size)
-                size = -1;
-
-            else if (total < 0)
-                size = -1;
-
-            else if ((pos + size) > total)
-                size = -1;
-
-            pSegment = new (std::nothrow) Segment(
-                                            pReader,
-                                            idpos,
-                                            //elem_size
-                                            pos,
-                                            size);
-
-            if (pSegment == 0)
-                return -1;  //generic error
-
-            return 0;    //success
-        }
-
-        if (size == unknown_size)
-            return E_FILE_FORMAT_INVALID;
-
-        if ((total >= 0) && ((pos + size) > total))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + size) > available)
-            return pos + size;
-
-        pos += size;  //consume payload
-    }
-}
-
-
-long long Segment::ParseHeaders()
-{
-    //Outermost (level 0) segment object has been constructed,
-    //and pos designates start of payload.  We need to find the
-    //inner (level 1) elements.
-    long long total, available;
-
-    const int status = m_pReader->Length(&total, &available);
-
-    if (status < 0) //error
+      if (status)
         return status;
+    } else if (id == 0x0C53BB6B) {  // Cues ID
+      if (m_pCues == NULL) {
+        m_pCues = new (std::nothrow)
+            Cues(this, pos, size, element_start, element_size);
 
-    assert((total < 0) || (available <= total));
+        if (m_pCues == NULL)
+          return -1;
+      }
+    } else if (id == 0x014D9B74) {  // SeekHead ID
+      if (m_pSeekHead == NULL) {
+        m_pSeekHead = new (std::nothrow)
+            SeekHead(this, pos, size, element_start, element_size);
 
-    const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
-    assert((segment_stop < 0) || (total < 0) || (segment_stop <= total));
-    assert((segment_stop < 0) || (m_pos <= segment_stop));
+        if (m_pSeekHead == NULL)
+          return -1;
 
-    for (;;)
-    {
-        if ((total >= 0) && (m_pos >= total))
-            break;
+        const long status = m_pSeekHead->Parse();
 
-        if ((segment_stop >= 0) && (m_pos >= segment_stop))
-            break;
+        if (status)
+          return status;
+      }
+    } else if (id == 0x0043A770) {  // Chapters ID
+      if (m_pChapters == NULL) {
+        m_pChapters = new (std::nothrow)
+            Chapters(this, pos, size, element_start, element_size);
 
-        long long pos = m_pos;
-        const long long element_start = pos;
+        if (m_pChapters == NULL)
+          return -1;
 
-        if ((pos + 1) > available)
-            return (pos + 1);
+        const long status = m_pChapters->Parse();
 
-        long len;
-        long long result = GetUIntLength(m_pReader, pos, len);
-
-        if (result < 0)  //error
-            return result;
-
-        if (result > 0)  //underflow (weird)
-            return (pos + 1);
-
-        if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + len) > available)
-            return pos + len;
-
-        const long long idpos = pos;
-        const long long id = ReadUInt(m_pReader, idpos, len);
-
-        if (id < 0)  //error
-            return id;
-
-        if (id == 0x0F43B675)  //Cluster ID
-            break;
-
-        pos += len;  //consume ID
-
-        if ((pos + 1) > available)
-            return (pos + 1);
-
-        //Read Size
-        result = GetUIntLength(m_pReader, pos, len);
-
-        if (result < 0)  //error
-            return result;
-
-        if (result > 0)  //underflow (weird)
-            return (pos + 1);
-
-        if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + len) > available)
-            return pos + len;
-
-        const long long size = ReadUInt(m_pReader, pos, len);
-
-        if (size < 0)  //error
-            return size;
-
-        pos += len;  //consume length of size of element
-
-        const long long element_size = size + pos - element_start;
-
-        //Pos now points to start of payload
-
-        if ((segment_stop >= 0) && ((pos + size) > segment_stop))
-            return E_FILE_FORMAT_INVALID;
-
-        //We read EBML elements either in total or nothing at all.
-
-        if ((pos + size) > available)
-            return pos + size;
-
-        if (id == 0x0549A966)  //Segment Info ID
-        {
-            if (m_pInfo)
-                return E_FILE_FORMAT_INVALID;
-
-            m_pInfo = new (std::nothrow) SegmentInfo(
-                                          this,
-                                          pos,
-                                          size,
-                                          element_start,
-                                          element_size);
-
-            if (m_pInfo == NULL)
-                return -1;
-
-            const long status = m_pInfo->Parse();
-
-            if (status)
-                return status;
-        }
-        else if (id == 0x0654AE6B)  //Tracks ID
-        {
-            if (m_pTracks)
-                return E_FILE_FORMAT_INVALID;
-
-            m_pTracks = new (std::nothrow) Tracks(this,
-                                                  pos,
-                                                  size,
-                                                  element_start,
-                                                  element_size);
-
-            if (m_pTracks == NULL)
-                return -1;
-
-            const long status = m_pTracks->Parse();
-
-            if (status)
-                return status;
-        }
-        else if (id == 0x0C53BB6B)  //Cues ID
-        {
-            if (m_pCues == NULL)
-            {
-                m_pCues = new (std::nothrow) Cues(
-                                                this,
-                                                pos,
-                                                size,
-                                                element_start,
-                                                element_size);
-
-                if (m_pCues == NULL)
-                    return -1;
-            }
-        }
-        else if (id == 0x014D9B74)  //SeekHead ID
-        {
-            if (m_pSeekHead == NULL)
-            {
-                m_pSeekHead = new (std::nothrow) SeekHead(
-                                                    this,
-                                                    pos,
-                                                    size,
-                                                    element_start,
-                                                    element_size);
-
-                if (m_pSeekHead == NULL)
-                    return -1;
-
-                const long status = m_pSeekHead->Parse();
-
-                if (status)
-                    return status;
-            }
-        }
-        else if (id == 0x0043A770)  //Chapters ID
-        {
-            if (m_pChapters == NULL)
-            {
-                m_pChapters = new (std::nothrow) Chapters(
-                                this,
-                                pos,
-                                size,
-                                element_start,
-                                element_size);
-
-                if (m_pChapters == NULL)
-                  return -1;
-
-                const long status = m_pChapters->Parse();
-
-                if (status)
-                  return status;
-            }
-        }
-
-        m_pos = pos + size;  //consume payload
+        if (status)
+          return status;
+      }
     }
 
-    assert((segment_stop < 0) || (m_pos <= segment_stop));
+    m_pos = pos + size;  // consume payload
+  }
 
-    if (m_pInfo == NULL)  //TODO: liberalize this behavior
-        return E_FILE_FORMAT_INVALID;
+  assert((segment_stop < 0) || (m_pos <= segment_stop));
 
-    if (m_pTracks == NULL)
-        return E_FILE_FORMAT_INVALID;
+  if (m_pInfo == NULL)  // TODO: liberalize this behavior
+    return E_FILE_FORMAT_INVALID;
 
-    return 0;  //success
+  if (m_pTracks == NULL)
+    return E_FILE_FORMAT_INVALID;
+
+  return 0;  // success
 }
 
+long Segment::LoadCluster(long long& pos, long& len) {
+  for (;;) {
+    const long result = DoLoadCluster(pos, len);
 
-long Segment::LoadCluster(
-    long long& pos,
-    long& len)
-{
-    for (;;)
-    {
-        const long result = DoLoadCluster(pos, len);
+    if (result <= 1)
+      return result;
+  }
+}
 
-        if (result <= 1)
-            return result;
+long Segment::DoLoadCluster(long long& pos, long& len) {
+  if (m_pos < 0)
+    return DoLoadClusterUnknownSize(pos, len);
+
+  long long total, avail;
+
+  long status = m_pReader->Length(&total, &avail);
+
+  if (status < 0)  // error
+    return status;
+
+  assert((total < 0) || (avail <= total));
+
+  const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
+
+  long long cluster_off = -1;  // offset relative to start of segment
+  long long cluster_size = -1;  // size of cluster payload
+
+  for (;;) {
+    if ((total >= 0) && (m_pos >= total))
+      return 1;  // no more clusters
+
+    if ((segment_stop >= 0) && (m_pos >= segment_stop))
+      return 1;  // no more clusters
+
+    pos = m_pos;
+
+    // Read ID
+
+    if ((pos + 1) > avail) {
+      len = 1;
+      return E_BUFFER_NOT_FULL;
     }
-}
 
+    long long result = GetUIntLength(m_pReader, pos, len);
 
-long Segment::DoLoadCluster(
-    long long& pos,
-    long& len)
-{
-    if (m_pos < 0)
-        return DoLoadClusterUnknownSize(pos, len);
+    if (result < 0)  // error
+      return static_cast<long>(result);
 
-    long long total, avail;
+    if (result > 0)  // weird
+      return E_BUFFER_NOT_FULL;
 
-    long status = m_pReader->Length(&total, &avail);
+    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+      return E_FILE_FORMAT_INVALID;
 
-    if (status < 0)  //error
-        return status;
+    if ((pos + len) > avail)
+      return E_BUFFER_NOT_FULL;
 
-    assert((total < 0) || (avail <= total));
+    const long long idpos = pos;
+    const long long id = ReadUInt(m_pReader, idpos, len);
 
-    const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
+    if (id < 0)  // error (or underflow)
+      return static_cast<long>(id);
 
-    long long cluster_off = -1;   //offset relative to start of segment
-    long long cluster_size = -1;  //size of cluster payload
+    pos += len;  // consume ID
 
-    for (;;)
-    {
-        if ((total >= 0) && (m_pos >= total))
-            return 1;  //no more clusters
+    // Read Size
 
-        if ((segment_stop >= 0) && (m_pos >= segment_stop))
-            return 1;  //no more clusters
+    if ((pos + 1) > avail) {
+      len = 1;
+      return E_BUFFER_NOT_FULL;
+    }
 
-        pos = m_pos;
+    result = GetUIntLength(m_pReader, pos, len);
 
-        //Read ID
+    if (result < 0)  // error
+      return static_cast<long>(result);
 
-        if ((pos + 1) > avail)
-        {
-            len = 1;
-            return E_BUFFER_NOT_FULL;
-        }
+    if (result > 0)  // weird
+      return E_BUFFER_NOT_FULL;
 
-        long long result = GetUIntLength(m_pReader, pos, len);
+    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+      return E_FILE_FORMAT_INVALID;
 
-        if (result < 0)  //error
-            return static_cast<long>(result);
+    if ((pos + len) > avail)
+      return E_BUFFER_NOT_FULL;
 
-        if (result > 0)  //weird
-            return E_BUFFER_NOT_FULL;
+    const long long size = ReadUInt(m_pReader, pos, len);
 
-        if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-            return E_FILE_FORMAT_INVALID;
+    if (size < 0)  // error
+      return static_cast<long>(size);
 
-        if ((pos + len) > avail)
-            return E_BUFFER_NOT_FULL;
+    pos += len;  // consume length of size of element
 
-        const long long idpos = pos;
-        const long long id = ReadUInt(m_pReader, idpos, len);
+    // pos now points to start of payload
 
-        if (id < 0)  //error (or underflow)
-            return static_cast<long>(id);
+    if (size == 0) {  // weird
+      m_pos = pos;
+      continue;
+    }
 
-        pos += len;  //consume ID
+    const long long unknown_size = (1LL << (7 * len)) - 1;
 
-        //Read Size
-
-        if ((pos + 1) > avail)
-        {
-            len = 1;
-            return E_BUFFER_NOT_FULL;
-        }
-
-        result = GetUIntLength(m_pReader, pos, len);
-
-        if (result < 0)  //error
-            return static_cast<long>(result);
-
-        if (result > 0)  //weird
-            return E_BUFFER_NOT_FULL;
-
-        if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-            return E_FILE_FORMAT_INVALID;
-
-        if ((pos + len) > avail)
-            return E_BUFFER_NOT_FULL;
-
-        const long long size = ReadUInt(m_pReader, pos, len);
-
-        if (size < 0)  //error
-            return static_cast<long>(size);
-
-        pos += len;  //consume length of size of element
-
-        //pos now points to start of payload
-
-        if (size == 0)  //weird
-        {
-            m_pos = pos;
-            continue;
-        }
-
-        const long long unknown_size = (1LL << (7 * len)) - 1;
-
-#if 0  //we must handle this to support live webm
+#if 0  // we must handle this to support live webm
         if (size == unknown_size)
             return E_FILE_FORMAT_INVALID;  //TODO: allow this
 #endif
 
-        if ((segment_stop >= 0) &&
-            (size != unknown_size) &&
-            ((pos + size) > segment_stop))
-        {
-            return E_FILE_FORMAT_INVALID;
-        }
+    if ((segment_stop >= 0) && (size != unknown_size) &&
+        ((pos + size) > segment_stop)) {
+      return E_FILE_FORMAT_INVALID;
+    }
 
-#if 0  //commented-out, to support incremental cluster parsing
+#if 0  // commented-out, to support incremental cluster parsing
         len = static_cast<long>(size);
 
         if ((pos + size) > avail)
             return E_BUFFER_NOT_FULL;
 #endif
 
-        if (id == 0x0C53BB6B)  //Cues ID
-        {
-            if (size == unknown_size)
-                return E_FILE_FORMAT_INVALID;  //TODO: liberalize
+    if (id == 0x0C53BB6B) {  // Cues ID
+      if (size == unknown_size)
+        return E_FILE_FORMAT_INVALID;  // TODO: liberalize
 
-            if (m_pCues == NULL)
-            {
-                const long long element_size = (pos - idpos) + size;
+      if (m_pCues == NULL) {
+        const long long element_size = (pos - idpos) + size;
 
-                m_pCues = new Cues(this,
-                                   pos,
-                                   size,
-                                   idpos,
-                                   element_size);
-                assert(m_pCues);  //TODO
-            }
+        m_pCues = new Cues(this, pos, size, idpos, element_size);
+        assert(m_pCues);  // TODO
+      }
 
-            m_pos = pos + size;  //consume payload
-            continue;
-        }
-
-        if (id != 0x0F43B675)  //Cluster ID
-        {
-            if (size == unknown_size)
-                return E_FILE_FORMAT_INVALID;  //TODO: liberalize
-
-            m_pos = pos + size;  //consume payload
-            continue;
-        }
-
-        //We have a cluster.
-
-        cluster_off = idpos - m_start;  //relative pos
-
-        if (size != unknown_size)
-            cluster_size = size;
-
-        break;
+      m_pos = pos + size;  // consume payload
+      continue;
     }
 
-    assert(cluster_off >= 0);  //have cluster
+    if (id != 0x0F43B675) {  // Cluster ID
+      if (size == unknown_size)
+        return E_FILE_FORMAT_INVALID;  // TODO: liberalize
 
-    long long pos_;
-    long len_;
-
-    status = Cluster::HasBlockEntries(this, cluster_off, pos_, len_);
-
-    if (status < 0) //error, or underflow
-    {
-        pos = pos_;
-        len = len_;
-
-        return status;
+      m_pos = pos + size;  // consume payload
+      continue;
     }
 
-    //status == 0 means "no block entries found"
-    //status > 0 means "found at least one block entry"
+    // We have a cluster.
 
-    //TODO:
-    //The issue here is that the segment increments its own
-    //pos ptr past the most recent cluster parsed, and then
-    //starts from there to parse the next cluster.  If we
-    //don't know the size of the current cluster, then we
-    //must either parse its payload (as we do below), looking
-    //for the cluster (or cues) ID to terminate the parse.
-    //This isn't really what we want: rather, we really need
-    //a way to create the curr cluster object immediately.
-    //The pity is that cluster::parse can determine its own
-    //boundary, and we largely duplicate that same logic here.
-    //
-    //Maybe we need to get rid of our look-ahead preloading
-    //in source::parse???
-    //
-    //As we're parsing the blocks in the curr cluster
-    //(in cluster::parse), we should have some way to signal
-    //to the segment that we have determined the boundary,
-    //so it can adjust its own segment::m_pos member.
-    //
-    //The problem is that we're asserting in asyncreadinit,
-    //because we adjust the pos down to the curr seek pos,
-    //and the resulting adjusted len is > 2GB.  I'm suspicious
-    //that this is even correct, but even if it is, we can't
-    //be loading that much data in the cache anyway.
+    cluster_off = idpos - m_start;  // relative pos
 
-    const long idx = m_clusterCount;
+    if (size != unknown_size)
+      cluster_size = size;
 
-    if (m_clusterPreloadCount > 0)
-    {
-        assert(idx < m_clusterSize);
+    break;
+  }
 
-        Cluster* const pCluster = m_clusters[idx];
-        assert(pCluster);
-        assert(pCluster->m_index < 0);
+  assert(cluster_off >= 0);  // have cluster
 
-        const long long off = pCluster->GetPosition();
-        assert(off >= 0);
+  long long pos_;
+  long len_;
 
-        if (off == cluster_off)  //preloaded already
-        {
-            if (status == 0)  //no entries found
-                return E_FILE_FORMAT_INVALID;
+  status = Cluster::HasBlockEntries(this, cluster_off, pos_, len_);
 
-            if (cluster_size >= 0)
-                pos += cluster_size;
-            else
-            {
-                const long long element_size = pCluster->GetElementSize();
+  if (status < 0) {  // error, or underflow
+    pos = pos_;
+    len = len_;
 
-                if (element_size <= 0)
-                    return E_FILE_FORMAT_INVALID;  //TODO: handle this case
+    return status;
+  }
 
-                pos = pCluster->m_element_start + element_size;
-            }
+  // status == 0 means "no block entries found"
+  // status > 0 means "found at least one block entry"
 
-            pCluster->m_index = idx;  //move from preloaded to loaded
-            ++m_clusterCount;
-            --m_clusterPreloadCount;
+  // TODO:
+  // The issue here is that the segment increments its own
+  // pos ptr past the most recent cluster parsed, and then
+  // starts from there to parse the next cluster.  If we
+  // don't know the size of the current cluster, then we
+  // must either parse its payload (as we do below), looking
+  // for the cluster (or cues) ID to terminate the parse.
+  // This isn't really what we want: rather, we really need
+  // a way to create the curr cluster object immediately.
+  // The pity is that cluster::parse can determine its own
+  // boundary, and we largely duplicate that same logic here.
+  //
+  // Maybe we need to get rid of our look-ahead preloading
+  // in source::parse???
+  //
+  // As we're parsing the blocks in the curr cluster
+  //(in cluster::parse), we should have some way to signal
+  // to the segment that we have determined the boundary,
+  // so it can adjust its own segment::m_pos member.
+  //
+  // The problem is that we're asserting in asyncreadinit,
+  // because we adjust the pos down to the curr seek pos,
+  // and the resulting adjusted len is > 2GB.  I'm suspicious
+  // that this is even correct, but even if it is, we can't
+  // be loading that much data in the cache anyway.
 
-            m_pos = pos;  //consume payload
-            assert((segment_stop < 0) || (m_pos <= segment_stop));
+  const long idx = m_clusterCount;
 
-            return 0;  //success
-        }
-    }
-
-    if (status == 0)  //no entries found
-    {
-        if (cluster_size < 0)
-            return E_FILE_FORMAT_INVALID;  //TODO: handle this
-
-        pos += cluster_size;
-
-        if ((total >= 0) && (pos >= total))
-        {
-            m_pos = total;
-            return 1;  //no more clusters
-        }
-
-        if ((segment_stop >= 0) && (pos >= segment_stop))
-        {
-            m_pos = segment_stop;
-            return 1;  //no more clusters
-        }
-
-        m_pos = pos;
-        return 2;  //try again
-    }
-
-    //status > 0 means we have an entry
-
-    Cluster* const pCluster = Cluster::Create(this,
-                                              idx,
-                                              cluster_off);
-                                              //element_size);
-    assert(pCluster);
-
-    AppendCluster(pCluster);
-    assert(m_clusters);
+  if (m_clusterPreloadCount > 0) {
     assert(idx < m_clusterSize);
-    assert(m_clusters[idx] == pCluster);
 
-    if (cluster_size >= 0)
-    {
+    Cluster* const pCluster = m_clusters[idx];
+    assert(pCluster);
+    assert(pCluster->m_index < 0);
+
+    const long long off = pCluster->GetPosition();
+    assert(off >= 0);
+
+    if (off == cluster_off) {  // preloaded already
+      if (status == 0)  // no entries found
+        return E_FILE_FORMAT_INVALID;
+
+      if (cluster_size >= 0)
         pos += cluster_size;
+      else {
+        const long long element_size = pCluster->GetElementSize();
 
-        m_pos = pos;
-        assert((segment_stop < 0) || (m_pos <= segment_stop));
+        if (element_size <= 0)
+          return E_FILE_FORMAT_INVALID;  // TODO: handle this case
 
-        return 0;
+        pos = pCluster->m_element_start + element_size;
+      }
+
+      pCluster->m_index = idx;  // move from preloaded to loaded
+      ++m_clusterCount;
+      --m_clusterPreloadCount;
+
+      m_pos = pos;  // consume payload
+      assert((segment_stop < 0) || (m_pos <= segment_stop));
+
+      return 0;  // success
+    }
+  }
+
+  if (status == 0) {  // no entries found
+    if (cluster_size < 0)
+      return E_FILE_FORMAT_INVALID;  // TODO: handle this
+
+    pos += cluster_size;
+
+    if ((total >= 0) && (pos >= total)) {
+      m_pos = total;
+      return 1;  // no more clusters
     }
 
-    m_pUnknownSize = pCluster;
-    m_pos = -pos;
+    if ((segment_stop >= 0) && (pos >= segment_stop)) {
+      m_pos = segment_stop;
+      return 1;  // no more clusters
+    }
 
-    return 0;  //partial success, since we have a new cluster
+    m_pos = pos;
+    return 2;  // try again
+  }
 
-    //status == 0 means "no block entries found"
+  // status > 0 means we have an entry
 
-    //pos designates start of payload
-    //m_pos has NOT been adjusted yet (in case we need to come back here)
+  Cluster* const pCluster = Cluster::Create(this, idx, cluster_off);
+  // element_size);
+  assert(pCluster);
+
+  AppendCluster(pCluster);
+  assert(m_clusters);
+  assert(idx < m_clusterSize);
+  assert(m_clusters[idx] == pCluster);
+
+  if (cluster_size >= 0) {
+    pos += cluster_size;
+
+    m_pos = pos;
+    assert((segment_stop < 0) || (m_pos <= segment_stop));
+
+    return 0;
+  }
+
+  m_pUnknownSize = pCluster;
+  m_pos = -pos;
+
+  return 0;  // partial success, since we have a new cluster
+
+// status == 0 means "no block entries found"
+
+// pos designates start of payload
+// m_pos has NOT been adjusted yet (in case we need to come back here)
 
 #if 0
 
-    if (cluster_size < 0)  //unknown size
-    {
+    if (cluster_size < 0) {  //unknown size
         const long long payload_pos = pos;  //absolute pos of cluster payload
 
-        for (;;)  //determine cluster size
-        {
+        for (;;) {  //determine cluster size
             if ((total >= 0) && (pos >= total))
                 break;
 
@@ -1518,16 +1346,11 @@

     return 2;     //try to find another cluster
 
 #endif
-
 }
 
-
-long Segment::DoLoadClusterUnknownSize(
-    long long& pos,
-    long& len)
-{
-    assert(m_pos < 0);
-    assert(m_pUnknownSize);
+long Segment::DoLoadClusterUnknownSize(long long& pos, long& len) {
+  assert(m_pos < 0);
+  assert(m_pUnknownSize);
 
 #if 0
     assert(m_pUnknownSize->GetElementSize() < 0);  //TODO: verify this
@@ -1554,8 +1377,7 @@

 
     long long element_size = -1;
 
-    for (;;)  //determine cluster size
-    {
+    for (;;) {  //determine cluster size
         if ((total >= 0) && (pos >= total))
         {
             element_size = total - element_start;
@@ -1604,8 +1426,7 @@

         //that we have exhausted the sub-element's inside the cluster
         //whose ID we parsed earlier.
 
-        if ((id == 0x0F43B675) || (id == 0x0C53BB6B)) //Cluster ID or Cues ID
-        {
+        if ((id == 0x0F43B675) || (id == 0x0C53BB6B)) {  //Cluster ID or Cues ID
             element_size = pos - element_start;
             assert(element_size > 0);
 
@@ -1682,348 +1503,299 @@

 
     return 2;  //continue parsing
 #else
-    const long status = m_pUnknownSize->Parse(pos, len);
+  const long status = m_pUnknownSize->Parse(pos, len);
 
-    if (status < 0)  //error or underflow
-        return status;
+  if (status < 0)  // error or underflow
+    return status;
 
-    if (status == 0)  //parsed a block
-        return 2;     //continue parsing
+  if (status == 0)  // parsed a block
+    return 2;  // continue parsing
 
-    assert(status > 0);   //nothing left to parse of this cluster
+  assert(status > 0);  // nothing left to parse of this cluster
 
-    const long long start = m_pUnknownSize->m_element_start;
+  const long long start = m_pUnknownSize->m_element_start;
 
-    const long long size = m_pUnknownSize->GetElementSize();
-    assert(size >= 0);
+  const long long size = m_pUnknownSize->GetElementSize();
+  assert(size >= 0);
 
-    pos = start + size;
-    m_pos = pos;
+  pos = start + size;
+  m_pos = pos;
 
-    m_pUnknownSize = 0;
+  m_pUnknownSize = 0;
 
-    return 2;  //continue parsing
+  return 2;  // continue parsing
 #endif
 }
 
+void Segment::AppendCluster(Cluster* pCluster) {
+  assert(pCluster);
+  assert(pCluster->m_index >= 0);
 
-void Segment::AppendCluster(Cluster* pCluster)
-{
-    assert(pCluster);
-    assert(pCluster->m_index >= 0);
+  const long count = m_clusterCount + m_clusterPreloadCount;
 
-    const long count = m_clusterCount + m_clusterPreloadCount;
+  long& size = m_clusterSize;
+  assert(size >= count);
 
-    long& size = m_clusterSize;
-    assert(size >= count);
+  const long idx = pCluster->m_index;
+  assert(idx == m_clusterCount);
 
-    const long idx = pCluster->m_index;
-    assert(idx == m_clusterCount);
+  if (count >= size) {
+    const long n = (size <= 0) ? 2048 : 2 * size;
 
-    if (count >= size)
-    {
-        const long n = (size <= 0) ? 2048 : 2*size;
+    Cluster** const qq = new Cluster* [n];
+    Cluster** q = qq;
 
-        Cluster** const qq = new Cluster*[n];
-        Cluster** q = qq;
+    Cluster** p = m_clusters;
+    Cluster** const pp = p + count;
 
-        Cluster** p = m_clusters;
-        Cluster** const pp = p + count;
+    while (p != pp)
+      *q++ = *p++;
 
-        while (p != pp)
-            *q++ = *p++;
+    delete[] m_clusters;
 
-        delete[] m_clusters;
+    m_clusters = qq;
+    size = n;
+  }
 
-        m_clusters = qq;
-        size = n;
-    }
-
-    if (m_clusterPreloadCount > 0)
-    {
-        assert(m_clusters);
-
-        Cluster** const p = m_clusters + m_clusterCount;
-        assert(*p);
-        assert((*p)->m_index < 0);
-
-        Cluster** q = p + m_clusterPreloadCount;
-        assert(q < (m_clusters + size));
-
-        for (;;)
-        {
-            Cluster** const qq = q - 1;
-            assert((*qq)->m_index < 0);
-
-            *q = *qq;
-            q = qq;
-
-            if (q == p)
-                break;
-        }
-    }
-
-    m_clusters[idx] = pCluster;
-    ++m_clusterCount;
-}
-
-
-void Segment::PreloadCluster(Cluster* pCluster, ptrdiff_t idx)
-{
-    assert(pCluster);
-    assert(pCluster->m_index < 0);
-    assert(idx >= m_clusterCount);
-
-    const long count = m_clusterCount + m_clusterPreloadCount;
-
-    long& size = m_clusterSize;
-    assert(size >= count);
-
-    if (count >= size)
-    {
-        const long n = (size <= 0) ? 2048 : 2*size;
-
-        Cluster** const qq = new Cluster*[n];
-        Cluster** q = qq;
-
-        Cluster** p = m_clusters;
-        Cluster** const pp = p + count;
-
-        while (p != pp)
-            *q++ = *p++;
-
-        delete[] m_clusters;
-
-        m_clusters = qq;
-        size = n;
-    }
-
+  if (m_clusterPreloadCount > 0) {
     assert(m_clusters);
 
-    Cluster** const p = m_clusters + idx;
+    Cluster** const p = m_clusters + m_clusterCount;
+    assert(*p);
+    assert((*p)->m_index < 0);
 
-    Cluster** q = m_clusters + count;
-    assert(q >= p);
+    Cluster** q = p + m_clusterPreloadCount;
     assert(q < (m_clusters + size));
 
-    while (q > p)
-    {
-        Cluster** const qq = q - 1;
-        assert((*qq)->m_index < 0);
+    for (;;) {
+      Cluster** const qq = q - 1;
+      assert((*qq)->m_index < 0);
 
-        *q = *qq;
-        q = qq;
+      *q = *qq;
+      q = qq;
+
+      if (q == p)
+        break;
     }
+  }
 
-    m_clusters[idx] = pCluster;
-    ++m_clusterPreloadCount;
+  m_clusters[idx] = pCluster;
+  ++m_clusterCount;
 }
 
+void Segment::PreloadCluster(Cluster* pCluster, ptrdiff_t idx) {
+  assert(pCluster);
+  assert(pCluster->m_index < 0);
+  assert(idx >= m_clusterCount);
 
-long Segment::Load()
-{
-    assert(m_clusters == NULL);
-    assert(m_clusterSize == 0);
-    assert(m_clusterCount == 0);
-    //assert(m_size >= 0);
+  const long count = m_clusterCount + m_clusterPreloadCount;
 
-    //Outermost (level 0) segment object has been constructed,
-    //and pos designates start of payload.  We need to find the
-    //inner (level 1) elements.
+  long& size = m_clusterSize;
+  assert(size >= count);
 
-    const long long header_status = ParseHeaders();
+  if (count >= size) {
+    const long n = (size <= 0) ? 2048 : 2 * size;
 
-    if (header_status < 0)  //error
-        return static_cast<long>(header_status);
+    Cluster** const qq = new Cluster* [n];
+    Cluster** q = qq;
 
-    if (header_status > 0)  //underflow
-        return E_BUFFER_NOT_FULL;
+    Cluster** p = m_clusters;
+    Cluster** const pp = p + count;
 
-    assert(m_pInfo);
-    assert(m_pTracks);
+    while (p != pp)
+      *q++ = *p++;
 
-    for (;;)
-    {
-        const int status = LoadCluster();
+    delete[] m_clusters;
 
-        if (status < 0)  //error
-            return status;
+    m_clusters = qq;
+    size = n;
+  }
 
-        if (status >= 1)  //no more clusters
-            return 0;
-    }
+  assert(m_clusters);
+
+  Cluster** const p = m_clusters + idx;
+
+  Cluster** q = m_clusters + count;
+  assert(q >= p);
+  assert(q < (m_clusters + size));
+
+  while (q > p) {
+    Cluster** const qq = q - 1;
+    assert((*qq)->m_index < 0);
+
+    *q = *qq;
+    q = qq;
+  }
+
+  m_clusters[idx] = pCluster;
+  ++m_clusterPreloadCount;
 }
 
+long Segment::Load() {
+  assert(m_clusters == NULL);
+  assert(m_clusterSize == 0);
+  assert(m_clusterCount == 0);
+  // assert(m_size >= 0);
 
-SeekHead::SeekHead(
-    Segment* pSegment,
-    long long start,
-    long long size_,
-    long long element_start,
-    long long element_size) :
-    m_pSegment(pSegment),
-    m_start(start),
-    m_size(size_),
-    m_element_start(element_start),
-    m_element_size(element_size),
-    m_entries(0),
-    m_entry_count(0),
-    m_void_elements(0),
-    m_void_element_count(0)
-{
+  // Outermost (level 0) segment object has been constructed,
+  // and pos designates start of payload.  We need to find the
+  // inner (level 1) elements.
+
+  const long long header_status = ParseHeaders();
+
+  if (header_status < 0)  // error
+    return static_cast<long>(header_status);
+
+  if (header_status > 0)  // underflow
+    return E_BUFFER_NOT_FULL;
+
+  assert(m_pInfo);
+  assert(m_pTracks);
+
+  for (;;) {
+    const int status = LoadCluster();
+
+    if (status < 0)  // error
+      return status;
+
+    if (status >= 1)  // no more clusters
+      return 0;
+  }
 }
 
+SeekHead::SeekHead(Segment* pSegment, long long start, long long size_,
+                   long long element_start, long long element_size)
+    : m_pSegment(pSegment),
+      m_start(start),
+      m_size(size_),
+      m_element_start(element_start),
+      m_element_size(element_size),
+      m_entries(0),
+      m_entry_count(0),
+      m_void_elements(0),
+      m_void_element_count(0) {}
 
-SeekHead::~SeekHead()
-{
-    delete[] m_entries;
-    delete[] m_void_elements;
+SeekHead::~SeekHead() {
+  delete[] m_entries;
+  delete[] m_void_elements;
 }
 
+long SeekHead::Parse() {
+  IMkvReader* const pReader = m_pSegment->m_pReader;
 
-long SeekHead::Parse()
-{
-    IMkvReader* const pReader = m_pSegment->m_pReader;
+  long long pos = m_start;
+  const long long stop = m_start + m_size;
 
-    long long pos = m_start;
-    const long long stop = m_start + m_size;
+  // first count the seek head entries
 
-    //first count the seek head entries
+  int entry_count = 0;
+  int void_element_count = 0;
 
-    int entry_count = 0;
-    int void_element_count = 0;
+  while (pos < stop) {
+    long long id, size;
 
-    while (pos < stop)
-    {
-        long long id, size;
+    const long status = ParseElementHeader(pReader, pos, stop, id, size);
 
-        const long status = ParseElementHeader(
-                                pReader,
-                                pos,
-                                stop,
-                                id,
-                                size);
+    if (status < 0)  // error
+      return status;
 
-        if (status < 0)  //error
-            return status;
+    if (id == 0x0DBB)  // SeekEntry ID
+      ++entry_count;
+    else if (id == 0x6C)  // Void ID
+      ++void_element_count;
 
-        if (id == 0x0DBB)  //SeekEntry ID
-            ++entry_count;
-        else if (id == 0x6C)  //Void ID
-            ++void_element_count;
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
 
-        pos += size;  //consume payload
-        assert(pos <= stop);
+  assert(pos == stop);
+
+  m_entries = new (std::nothrow) Entry[entry_count];
+
+  if (m_entries == NULL)
+    return -1;
+
+  m_void_elements = new (std::nothrow) VoidElement[void_element_count];
+
+  if (m_void_elements == NULL)
+    return -1;
+
+  // now parse the entries and void elements
+
+  Entry* pEntry = m_entries;
+  VoidElement* pVoidElement = m_void_elements;
+
+  pos = m_start;
+
+  while (pos < stop) {
+    const long long idpos = pos;
+
+    long long id, size;
+
+    const long status = ParseElementHeader(pReader, pos, stop, id, size);
+
+    if (status < 0)  // error
+      return status;
+
+    if (id == 0x0DBB) {  // SeekEntry ID
+      if (ParseEntry(pReader, pos, size, pEntry)) {
+        Entry& e = *pEntry++;
+
+        e.element_start = idpos;
+        e.element_size = (pos + size) - idpos;
+      }
+    } else if (id == 0x6C) {  // Void ID
+      VoidElement& e = *pVoidElement++;
+
+      e.element_start = idpos;
+      e.element_size = (pos + size) - idpos;
     }
 
-    assert(pos == stop);
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
 
-    m_entries = new (std::nothrow) Entry[entry_count];
+  assert(pos == stop);
 
-    if (m_entries == NULL)
-        return -1;
+  ptrdiff_t count_ = ptrdiff_t(pEntry - m_entries);
+  assert(count_ >= 0);
+  assert(count_ <= entry_count);
 
-    m_void_elements = new (std::nothrow) VoidElement[void_element_count];
+  m_entry_count = static_cast<int>(count_);
 
-    if (m_void_elements == NULL)
-        return -1;
+  count_ = ptrdiff_t(pVoidElement - m_void_elements);
+  assert(count_ >= 0);
+  assert(count_ <= void_element_count);
 
-    //now parse the entries and void elements
+  m_void_element_count = static_cast<int>(count_);
 
-    Entry* pEntry = m_entries;
-    VoidElement* pVoidElement = m_void_elements;
+  return 0;
+}
 
-    pos = m_start;
+int SeekHead::GetCount() const { return m_entry_count; }
 
-    while (pos < stop)
-    {
-        const long long idpos = pos;
-
-        long long id, size;
-
-        const long status = ParseElementHeader(
-                                pReader,
-                                pos,
-                                stop,
-                                id,
-                                size);
-
-        if (status < 0)  //error
-            return status;
-
-        if (id == 0x0DBB)  //SeekEntry ID
-        {
-            if (ParseEntry(pReader, pos, size, pEntry))
-            {
-                Entry& e = *pEntry++;
-
-                e.element_start = idpos;
-                e.element_size = (pos + size) - idpos;
-            }
-        }
-        else if (id == 0x6C)  //Void ID
-        {
-            VoidElement& e = *pVoidElement++;
-
-            e.element_start = idpos;
-            e.element_size = (pos + size) - idpos;
-        }
-
-        pos += size;  //consume payload
-        assert(pos <= stop);
-    }
-
-    assert(pos == stop);
-
-    ptrdiff_t count_ = ptrdiff_t(pEntry - m_entries);
-    assert(count_ >= 0);
-    assert(count_ <= entry_count);
-
-    m_entry_count = static_cast<int>(count_);
-
-    count_ = ptrdiff_t(pVoidElement - m_void_elements);
-    assert(count_ >= 0);
-    assert(count_ <= void_element_count);
-
-    m_void_element_count = static_cast<int>(count_);
-
+const SeekHead::Entry* SeekHead::GetEntry(int idx) const {
+  if (idx < 0)
     return 0;
+
+  if (idx >= m_entry_count)
+    return 0;
+
+  return m_entries + idx;
 }
 
+int SeekHead::GetVoidElementCount() const { return m_void_element_count; }
 
-int SeekHead::GetCount() const
-{
-    return m_entry_count;
+const SeekHead::VoidElement* SeekHead::GetVoidElement(int idx) const {
+  if (idx < 0)
+    return 0;
+
+  if (idx >= m_void_element_count)
+    return 0;
+
+  return m_void_elements + idx;
 }
 
-const SeekHead::Entry* SeekHead::GetEntry(int idx) const
-{
-    if (idx < 0)
-        return 0;
-
-    if (idx >= m_entry_count)
-        return 0;
-
-    return m_entries + idx;
-}
-
-int SeekHead::GetVoidElementCount() const
-{
-    return m_void_element_count;
-}
-
-const SeekHead::VoidElement* SeekHead::GetVoidElement(int idx) const
-{
-    if (idx < 0)
-        return 0;
-
-    if (idx >= m_void_element_count)
-        return 0;
-
-    return m_void_elements + idx;
-}
-
-
 #if 0
 void Segment::ParseCues(long long off)
 {
@@ -2073,133 +1845,122 @@

     //os << "Segment::ParseCues (end)" << endl;
 }
 #else
-long Segment::ParseCues(
-    long long off,
-    long long& pos,
-    long& len)
-{
-    if (m_pCues)
-        return 0;  //success
+long Segment::ParseCues(long long off, long long& pos, long& len) {
+  if (m_pCues)
+    return 0;  // success
 
-    if (off < 0)
-        return -1;
+  if (off < 0)
+    return -1;
 
-    long long total, avail;
+  long long total, avail;
 
-    const int status = m_pReader->Length(&total, &avail);
+  const int status = m_pReader->Length(&total, &avail);
 
-    if (status < 0)  //error
-        return status;
+  if (status < 0)  // error
+    return status;
 
-    assert((total < 0) || (avail <= total));
+  assert((total < 0) || (avail <= total));
 
-    pos = m_start + off;
+  pos = m_start + off;
 
-    if ((total < 0) || (pos >= total))
-        return 1;  //don't bother parsing cues
+  if ((total < 0) || (pos >= total))
+    return 1;  // don't bother parsing cues
 
-    const long long element_start = pos;
-    const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
+  const long long element_start = pos;
+  const long long segment_stop = (m_size < 0) ? -1 : m_start + m_size;
 
-    if ((pos + 1) > avail)
-    {
-        len = 1;
-        return E_BUFFER_NOT_FULL;
-    }
+  if ((pos + 1) > avail) {
+    len = 1;
+    return E_BUFFER_NOT_FULL;
+  }
 
-    long long result = GetUIntLength(m_pReader, pos, len);
+  long long result = GetUIntLength(m_pReader, pos, len);
 
-    if (result < 0)  //error
-        return static_cast<long>(result);
+  if (result < 0)  // error
+    return static_cast<long>(result);
 
-    if (result > 0) //underflow (weird)
-    {
-        len = 1;
-        return E_BUFFER_NOT_FULL;
-    }
+  if (result > 0)  // underflow (weird)
+  {
+    len = 1;
+    return E_BUFFER_NOT_FULL;
+  }
 
-    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-        return E_FILE_FORMAT_INVALID;
+  if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((pos + len) > avail)
-        return E_BUFFER_NOT_FULL;
+  if ((pos + len) > avail)
+    return E_BUFFER_NOT_FULL;
 
-    const long long idpos = pos;
+  const long long idpos = pos;
 
-    const long long id = ReadUInt(m_pReader, idpos, len);
+  const long long id = ReadUInt(m_pReader, idpos, len);
 
-    if (id != 0x0C53BB6B)  //Cues ID
-        return E_FILE_FORMAT_INVALID;
+  if (id != 0x0C53BB6B)  // Cues ID
+    return E_FILE_FORMAT_INVALID;
 
-    pos += len;  //consume ID
-    assert((segment_stop < 0) || (pos <= segment_stop));
+  pos += len;  // consume ID
+  assert((segment_stop < 0) || (pos <= segment_stop));
 
-    //Read Size
+  // Read Size
 
-    if ((pos + 1) > avail)
-    {
-        len = 1;
-        return E_BUFFER_NOT_FULL;
-    }
+  if ((pos + 1) > avail) {
+    len = 1;
+    return E_BUFFER_NOT_FULL;
+  }
 
-    result = GetUIntLength(m_pReader, pos, len);
+  result = GetUIntLength(m_pReader, pos, len);
 
-    if (result < 0)  //error
-        return static_cast<long>(result);
+  if (result < 0)  // error
+    return static_cast<long>(result);
 
-    if (result > 0) //underflow (weird)
-    {
-        len = 1;
-        return E_BUFFER_NOT_FULL;
-    }
+  if (result > 0)  // underflow (weird)
+  {
+    len = 1;
+    return E_BUFFER_NOT_FULL;
+  }
 
-    if ((segment_stop >= 0) && ((pos + len) > segment_stop))
-        return E_FILE_FORMAT_INVALID;
+  if ((segment_stop >= 0) && ((pos + len) > segment_stop))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((pos + len) > avail)
-        return E_BUFFER_NOT_FULL;
+  if ((pos + len) > avail)
+    return E_BUFFER_NOT_FULL;
 
-    const long long size = ReadUInt(m_pReader, pos, len);
+  const long long size = ReadUInt(m_pReader, pos, len);
 
-    if (size < 0)  //error
-        return static_cast<long>(size);
+  if (size < 0)  // error
+    return static_cast<long>(size);
 
-    if (size == 0)  //weird, although technically not illegal
-        return 1;   //done
+  if (size == 0)  // weird, although technically not illegal
+    return 1;  // done
 
-    pos += len;  //consume length of size of element
-    assert((segment_stop < 0) || (pos <= segment_stop));
+  pos += len;  // consume length of size of element
+  assert((segment_stop < 0) || (pos <= segment_stop));
 
-    //Pos now points to start of payload
+  // Pos now points to start of payload
 
-    const long long element_stop = pos + size;
+  const long long element_stop = pos + size;
 
-    if ((segment_stop >= 0) && (element_stop > segment_stop))
-        return E_FILE_FORMAT_INVALID;
+  if ((segment_stop >= 0) && (element_stop > segment_stop))
+    return E_FILE_FORMAT_INVALID;
 
-    if ((total >= 0) && (element_stop > total))
-        return 1;  //don't bother parsing anymore
+  if ((total >= 0) && (element_stop > total))
+    return 1;  // don't bother parsing anymore
 
-    len = static_cast<long>(size);
+  len = static_cast<long>(size);
 
-    if (element_stop > avail)
-        return E_BUFFER_NOT_FULL;
+  if (element_stop > avail)
+    return E_BUFFER_NOT_FULL;
 
-    const long long element_size = element_stop - element_start;
+  const long long element_size = element_stop - element_start;
 
-    m_pCues = new (std::nothrow) Cues(
-                                    this,
-                                    pos,
-                                    size,
-                                    element_start,
-                                    element_size);
-    assert(m_pCues);  //TODO
+  m_pCues =
+      new (std::nothrow) Cues(this, pos, size, element_start, element_size);
+  assert(m_pCues);  // TODO
 
-    return 0;  //success
+  return 0;  // success
 }
 #endif
 
-
 #if 0
 void Segment::ParseSeekEntry(
     long long start,
@@ -2259,304 +2020,269 @@

         ParseCues(seekOff);
 }
 #else
-bool SeekHead::ParseEntry(
-    IMkvReader* pReader,
-    long long start,
-    long long size_,
-    Entry* pEntry)
-{
-    if (size_ <= 0)
-        return false;
+bool SeekHead::ParseEntry(IMkvReader* pReader, long long start, long long size_,
+                          Entry* pEntry) {
+  if (size_ <= 0)
+    return false;
 
-    long long pos = start;
-    const long long stop = start + size_;
+  long long pos = start;
+  const long long stop = start + size_;
 
-    long len;
+  long len;
 
-    //parse the container for the level-1 element ID
+  // parse the container for the level-1 element ID
 
-    const long long seekIdId = ReadUInt(pReader, pos, len);
-    //seekIdId;
+  const long long seekIdId = ReadUInt(pReader, pos, len);
+  // seekIdId;
 
-    if (seekIdId != 0x13AB)  //SeekID ID
-        return false;
+  if (seekIdId != 0x13AB)  // SeekID ID
+    return false;
 
-    if ((pos + len) > stop)
-        return false;
+  if ((pos + len) > stop)
+    return false;
 
-    pos += len;  //consume SeekID id
+  pos += len;  // consume SeekID id
 
-    const long long seekIdSize = ReadUInt(pReader, pos, len);
+  const long long seekIdSize = ReadUInt(pReader, pos, len);
 
-    if (seekIdSize <= 0)
-        return false;
+  if (seekIdSize <= 0)
+    return false;
 
-    if ((pos + len) > stop)
-        return false;
+  if ((pos + len) > stop)
+    return false;
 
-    pos += len;  //consume size of field
+  pos += len;  // consume size of field
 
-    if ((pos + seekIdSize) > stop)
-        return false;
+  if ((pos + seekIdSize) > stop)
+    return false;
 
-    //Note that the SeekId payload really is serialized
-    //as a "Matroska integer", not as a plain binary value.
-    //In fact, Matroska requires that ID values in the
-    //stream exactly match the binary representation as listed
-    //in the Matroska specification.
-    //
-    //This parser is more liberal, and permits IDs to have
-    //any width.  (This could make the representation in the stream
-    //different from what's in the spec, but it doesn't matter here,
-    //since we always normalize "Matroska integer" values.)
+  // Note that the SeekId payload really is serialized
+  // as a "Matroska integer", not as a plain binary value.
+  // In fact, Matroska requires that ID values in the
+  // stream exactly match the binary representation as listed
+  // in the Matroska specification.
+  //
+  // This parser is more liberal, and permits IDs to have
+  // any width.  (This could make the representation in the stream
+  // different from what's in the spec, but it doesn't matter here,
+  // since we always normalize "Matroska integer" values.)
 
-    pEntry->id = ReadUInt(pReader, pos, len);  //payload
+  pEntry->id = ReadUInt(pReader, pos, len);  // payload
 
-    if (pEntry->id <= 0)
-        return false;
+  if (pEntry->id <= 0)
+    return false;
 
-    if (len != seekIdSize)
-        return false;
+  if (len != seekIdSize)
+    return false;
 
-    pos += seekIdSize;  //consume SeekID payload
+  pos += seekIdSize;  // consume SeekID payload
 
-    const long long seekPosId = ReadUInt(pReader, pos, len);
+  const long long seekPosId = ReadUInt(pReader, pos, len);
 
-    if (seekPosId != 0x13AC)  //SeekPos ID
-        return false;
+  if (seekPosId != 0x13AC)  // SeekPos ID
+    return false;
 
-    if ((pos + len) > stop)
-        return false;
+  if ((pos + len) > stop)
+    return false;
 
-    pos += len;  //consume id
+  pos += len;  // consume id
 
-    const long long seekPosSize = ReadUInt(pReader, pos, len);
+  const long long seekPosSize = ReadUInt(pReader, pos, len);
 
-    if (seekPosSize <= 0)
-        return false;
+  if (seekPosSize <= 0)
+    return false;
 
-    if ((pos + len) > stop)
-        return false;
+  if ((pos + len) > stop)
+    return false;
 
-    pos += len;  //consume size
+  pos += len;  // consume size
 
-    if ((pos + seekPosSize) > stop)
-        return false;
+  if ((pos + seekPosSize) > stop)
+    return false;
 
-    pEntry->pos = UnserializeUInt(pReader, pos, seekPosSize);
+  pEntry->pos = UnserializeUInt(pReader, pos, seekPosSize);
 
-    if (pEntry->pos < 0)
-        return false;
+  if (pEntry->pos < 0)
+    return false;
 
-    pos += seekPosSize;  //consume payload
+  pos += seekPosSize;  // consume payload
 
-    if (pos != stop)
-        return false;
+  if (pos != stop)
+    return false;
 
-    return true;
+  return true;
 }
 #endif
 
+Cues::Cues(Segment* pSegment, long long start_, long long size_,
+           long long element_start, long long element_size)
+    : m_pSegment(pSegment),
+      m_start(start_),
+      m_size(size_),
+      m_element_start(element_start),
+      m_element_size(element_size),
+      m_cue_points(NULL),
+      m_count(0),
+      m_preload_count(0),
+      m_pos(start_) {}
 
-Cues::Cues(
-    Segment* pSegment,
-    long long start_,
-    long long size_,
-    long long element_start,
-    long long element_size) :
-    m_pSegment(pSegment),
-    m_start(start_),
-    m_size(size_),
-    m_element_start(element_start),
-    m_element_size(element_size),
-    m_cue_points(NULL),
-    m_count(0),
-    m_preload_count(0),
-    m_pos(start_)
-{
+Cues::~Cues() {
+  const long n = m_count + m_preload_count;
+
+  CuePoint** p = m_cue_points;
+  CuePoint** const q = p + n;
+
+  while (p != q) {
+    CuePoint* const pCP = *p++;
+    assert(pCP);
+
+    delete pCP;
+  }
+
+  delete[] m_cue_points;
 }
 
+long Cues::GetCount() const {
+  if (m_cue_points == NULL)
+    return -1;
 
-Cues::~Cues()
-{
-    const long n = m_count + m_preload_count;
+  return m_count;  // TODO: really ignore preload count?
+}
 
-    CuePoint** p = m_cue_points;
-    CuePoint** const q = p + n;
+bool Cues::DoneParsing() const {
+  const long long stop = m_start + m_size;
+  return (m_pos >= stop);
+}
 
-    while (p != q)
-    {
-        CuePoint* const pCP = *p++;
-        assert(pCP);
+void Cues::Init() const {
+  if (m_cue_points)
+    return;
 
-        delete pCP;
-    }
+  assert(m_count == 0);
+  assert(m_preload_count == 0);
+
+  IMkvReader* const pReader = m_pSegment->m_pReader;
+
+  const long long stop = m_start + m_size;
+  long long pos = m_start;
+
+  long cue_points_size = 0;
+
+  while (pos < stop) {
+    const long long idpos = pos;
+
+    long len;
+
+    const long long id = ReadUInt(pReader, pos, len);
+    assert(id >= 0);  // TODO
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume ID
+
+    const long long size = ReadUInt(pReader, pos, len);
+    assert(size >= 0);
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume Size field
+    assert((pos + size) <= stop);
+
+    if (id == 0x3B)  // CuePoint ID
+      PreloadCuePoint(cue_points_size, idpos);
+
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
+}
+
+void Cues::PreloadCuePoint(long& cue_points_size, long long pos) const {
+  assert(m_count == 0);
+
+  if (m_preload_count >= cue_points_size) {
+    const long n = (cue_points_size <= 0) ? 2048 : 2 * cue_points_size;
+
+    CuePoint** const qq = new CuePoint* [n];
+    CuePoint** q = qq;  // beginning of target
+
+    CuePoint** p = m_cue_points;  // beginning of source
+    CuePoint** const pp = p + m_preload_count;  // end of source
+
+    while (p != pp)
+      *q++ = *p++;
 
     delete[] m_cue_points;
+
+    m_cue_points = qq;
+    cue_points_size = n;
+  }
+
+  CuePoint* const pCP = new CuePoint(m_preload_count, pos);
+  m_cue_points[m_preload_count++] = pCP;
 }
 
+bool Cues::LoadCuePoint() const {
+  // odbgstream os;
+  // os << "Cues::LoadCuePoint" << endl;
 
-long Cues::GetCount() const
-{
-    if (m_cue_points == NULL)
-        return -1;
+  const long long stop = m_start + m_size;
 
-    return m_count;  //TODO: really ignore preload count?
-}
+  if (m_pos >= stop)
+    return false;  // nothing else to do
 
+  Init();
 
-bool Cues::DoneParsing() const
-{
-    const long long stop = m_start + m_size;
-    return (m_pos >= stop);
-}
+  IMkvReader* const pReader = m_pSegment->m_pReader;
 
+  while (m_pos < stop) {
+    const long long idpos = m_pos;
 
-void Cues::Init() const
-{
-    if (m_cue_points)
-        return;
+    long len;
 
-    assert(m_count == 0);
-    assert(m_preload_count == 0);
+    const long long id = ReadUInt(pReader, m_pos, len);
+    assert(id >= 0);  // TODO
+    assert((m_pos + len) <= stop);
 
-    IMkvReader* const pReader = m_pSegment->m_pReader;
+    m_pos += len;  // consume ID
 
-    const long long stop = m_start + m_size;
-    long long pos = m_start;
+    const long long size = ReadUInt(pReader, m_pos, len);
+    assert(size >= 0);
+    assert((m_pos + len) <= stop);
 
-    long cue_points_size = 0;
+    m_pos += len;  // consume Size field
+    assert((m_pos + size) <= stop);
 
-    while (pos < stop)
-    {
-        const long long idpos = pos;
+    if (id != 0x3B) {  // CuePoint ID
+      m_pos += size;  // consume payload
+      assert(m_pos <= stop);
 
-        long len;
-
-        const long long id = ReadUInt(pReader, pos, len);
-        assert(id >= 0);  //TODO
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume ID
-
-        const long long size = ReadUInt(pReader, pos, len);
-        assert(size >= 0);
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume Size field
-        assert((pos + size) <= stop);
-
-        if (id == 0x3B)  //CuePoint ID
-            PreloadCuePoint(cue_points_size, idpos);
-
-        pos += size;  //consume payload
-        assert(pos <= stop);
-    }
-}
-
-
-void Cues::PreloadCuePoint(
-    long& cue_points_size,
-    long long pos) const
-{
-    assert(m_count == 0);
-
-    if (m_preload_count >= cue_points_size)
-    {
-        const long n = (cue_points_size <= 0) ? 2048 : 2*cue_points_size;
-
-        CuePoint** const qq = new CuePoint*[n];
-        CuePoint** q = qq;  //beginning of target
-
-        CuePoint** p = m_cue_points;                //beginning of source
-        CuePoint** const pp = p + m_preload_count;  //end of source
-
-        while (p != pp)
-            *q++ = *p++;
-
-        delete[] m_cue_points;
-
-        m_cue_points = qq;
-        cue_points_size = n;
+      continue;
     }
 
-    CuePoint* const pCP = new CuePoint(m_preload_count, pos);
-    m_cue_points[m_preload_count++] = pCP;
+    assert(m_preload_count > 0);
+
+    CuePoint* const pCP = m_cue_points[m_count];
+    assert(pCP);
+    assert((pCP->GetTimeCode() >= 0) || (-pCP->GetTimeCode() == idpos));
+    if (pCP->GetTimeCode() < 0 && (-pCP->GetTimeCode() != idpos))
+      return false;
+
+    pCP->Load(pReader);
+    ++m_count;
+    --m_preload_count;
+
+    m_pos += size;  // consume payload
+    assert(m_pos <= stop);
+
+    return true;  // yes, we loaded a cue point
+  }
+
+  // return (m_pos < stop);
+  return false;  // no, we did not load a cue point
 }
 
-
-bool Cues::LoadCuePoint() const
-{
-    //odbgstream os;
-    //os << "Cues::LoadCuePoint" << endl;
-
-    const long long stop = m_start + m_size;
-
-    if (m_pos >= stop)
-        return false;  //nothing else to do
-
-    Init();
-
-    IMkvReader* const pReader = m_pSegment->m_pReader;
-
-    while (m_pos < stop)
-    {
-        const long long idpos = m_pos;
-
-        long len;
-
-        const long long id = ReadUInt(pReader, m_pos, len);
-        assert(id >= 0);  //TODO
-        assert((m_pos + len) <= stop);
-
-        m_pos += len;  //consume ID
-
-        const long long size = ReadUInt(pReader, m_pos, len);
-        assert(size >= 0);
-        assert((m_pos + len) <= stop);
-
-        m_pos += len;  //consume Size field
-        assert((m_pos + size) <= stop);
-
-        if (id != 0x3B)  //CuePoint ID
-        {
-            m_pos += size;  //consume payload
-            assert(m_pos <= stop);
-
-            continue;
-        }
-
-        assert(m_preload_count > 0);
-
-        CuePoint* const pCP = m_cue_points[m_count];
-        assert(pCP);
-        assert((pCP->GetTimeCode() >= 0) || (-pCP->GetTimeCode() == idpos));
-        if (pCP->GetTimeCode() < 0 && (-pCP->GetTimeCode() != idpos))
-            return false;
-
-        pCP->Load(pReader);
-        ++m_count;
-        --m_preload_count;
-
-        m_pos += size;  //consume payload
-        assert(m_pos <= stop);
-
-        return true;  //yes, we loaded a cue point
-    }
-
-    //return (m_pos < stop);
-    return false;  //no, we did not load a cue point
-}
-
-
-bool Cues::Find(
-    long long time_ns,
-    const Track* pTrack,
-    const CuePoint*& pCP,
-    const CuePoint::TrackPosition*& pTP) const
-{
-    assert(time_ns >= 0);
-    assert(pTrack);
+bool Cues::Find(long long time_ns, const Track* pTrack, const CuePoint*& pCP,
+                const CuePoint::TrackPosition*& pTP) const {
+  assert(time_ns >= 0);
+  assert(pTrack);
 
 #if 0
     LoadCuePoint();  //establish invariant
@@ -2614,71 +2340,68 @@

     assert(pCP);
     assert(pCP->GetTime(m_pSegment) <= time_ns);
 #else
-    if (m_cue_points == NULL)
-        return false;
+  if (m_cue_points == NULL)
+    return false;
 
-    if (m_count == 0)
-        return false;
+  if (m_count == 0)
+    return false;
 
-    CuePoint** const ii = m_cue_points;
-    CuePoint** i = ii;
+  CuePoint** const ii = m_cue_points;
+  CuePoint** i = ii;
 
-    CuePoint** const jj = ii + m_count;
-    CuePoint** j = jj;
+  CuePoint** const jj = ii + m_count;
+  CuePoint** j = jj;
 
-    pCP = *i;
-    assert(pCP);
+  pCP = *i;
+  assert(pCP);
 
-    if (time_ns <= pCP->GetTime(m_pSegment))
-    {
-        pTP = pCP->Find(pTrack);
-        return (pTP != NULL);
-    }
-
-    while (i < j)
-    {
-        //INVARIANT:
-        //[ii, i) <= time_ns
-        //[i, j)  ?
-        //[j, jj) > time_ns
-
-        CuePoint** const k = i + (j - i) / 2;
-        assert(k < jj);
-
-        CuePoint* const pCP = *k;
-        assert(pCP);
-
-        const long long t = pCP->GetTime(m_pSegment);
-
-        if (t <= time_ns)
-            i = k + 1;
-        else
-            j = k;
-
-        assert(i <= j);
-    }
-
-    assert(i == j);
-    assert(i <= jj);
-    assert(i > ii);
-
-    pCP = *--i;
-    assert(pCP);
-    assert(pCP->GetTime(m_pSegment) <= time_ns);
-#endif
-
-    //TODO: here and elsewhere, it's probably not correct to search
-    //for the cue point with this time, and then search for a matching
-    //track.  In principle, the matching track could be on some earlier
-    //cue point, and with our current algorithm, we'd miss it.  To make
-    //this bullet-proof, we'd need to create a secondary structure,
-    //with a list of cue points that apply to a track, and then search
-    //that track-based structure for a matching cue point.
-
+  if (time_ns <= pCP->GetTime(m_pSegment)) {
     pTP = pCP->Find(pTrack);
     return (pTP != NULL);
-}
+  }
 
+  while (i < j) {
+    // INVARIANT:
+    //[ii, i) <= time_ns
+    //[i, j)  ?
+    //[j, jj) > time_ns
+
+    CuePoint** const k = i + (j - i) / 2;
+    assert(k < jj);
+
+    CuePoint* const pCP = *k;
+    assert(pCP);
+
+    const long long t = pCP->GetTime(m_pSegment);
+
+    if (t <= time_ns)
+      i = k + 1;
+    else
+      j = k;
+
+    assert(i <= j);
+  }
+
+  assert(i == j);
+  assert(i <= jj);
+  assert(i > ii);
+
+  pCP = *--i;
+  assert(pCP);
+  assert(pCP->GetTime(m_pSegment) <= time_ns);
+#endif
+
+  // TODO: here and elsewhere, it's probably not correct to search
+  // for the cue point with this time, and then search for a matching
+  // track.  In principle, the matching track could be on some earlier
+  // cue point, and with our current algorithm, we'd miss it.  To make
+  // this bullet-proof, we'd need to create a secondary structure,
+  // with a list of cue points that apply to a track, and then search
+  // that track-based structure for a matching cue point.
+
+  pTP = pCP->Find(pTrack);
+  return (pTP != NULL);
+}
 
 #if 0
 bool Cues::FindNext(
@@ -2739,14 +2462,12 @@

 }
 #endif
 
+const CuePoint* Cues::GetFirst() const {
+  if (m_cue_points == NULL)
+    return NULL;
 
-const CuePoint* Cues::GetFirst() const
-{
-    if (m_cue_points == NULL)
-        return NULL;
-
-    if (m_count == 0)
-        return NULL;
+  if (m_count == 0)
+    return NULL;
 
 #if 0
     LoadCuePoint();  //init cues
@@ -2757,24 +2478,22 @@

         return NULL;
 #endif
 
-    CuePoint* const* const pp = m_cue_points;
-    assert(pp);
+  CuePoint* const* const pp = m_cue_points;
+  assert(pp);
 
-    CuePoint* const pCP = pp[0];
-    assert(pCP);
-    assert(pCP->GetTimeCode() >= 0);
+  CuePoint* const pCP = pp[0];
+  assert(pCP);
+  assert(pCP->GetTimeCode() >= 0);
 
-    return pCP;
+  return pCP;
 }
 
+const CuePoint* Cues::GetLast() const {
+  if (m_cue_points == NULL)
+    return NULL;
 
-const CuePoint* Cues::GetLast() const
-{
-    if (m_cue_points == NULL)
-        return NULL;
-
-    if (m_count <= 0)
-        return NULL;
+  if (m_count <= 0)
+    return NULL;
 
 #if 0
     LoadCuePoint();  //init cues
@@ -2795,28 +2514,26 @@

     pCP->Load(m_pSegment->m_pReader);
     assert(pCP->GetTimeCode() >= 0);
 #else
-    const long index = m_count - 1;
+  const long index = m_count - 1;
 
-    CuePoint* const* const pp = m_cue_points;
-    assert(pp);
+  CuePoint* const* const pp = m_cue_points;
+  assert(pp);
 
-    CuePoint* const pCP = pp[index];
-    assert(pCP);
-    assert(pCP->GetTimeCode() >= 0);
+  CuePoint* const pCP = pp[index];
+  assert(pCP);
+  assert(pCP->GetTimeCode() >= 0);
 #endif
 
-    return pCP;
+  return pCP;
 }
 
+const CuePoint* Cues::GetNext(const CuePoint* pCurr) const {
+  if (pCurr == NULL)
+    return NULL;
 
-const CuePoint* Cues::GetNext(const CuePoint* pCurr) const
-{
-    if (pCurr == NULL)
-        return NULL;
-
-    assert(pCurr->GetTimeCode() >= 0);
-    assert(m_cue_points);
-    assert(m_count >= 1);
+  assert(pCurr->GetTimeCode() >= 0);
+  assert(m_cue_points);
+  assert(m_count >= 1);
 
 #if 0
     const size_t count = m_count + m_preload_count;
@@ -2838,386 +2555,347 @@

 
     pNext->Load(m_pSegment->m_pReader);
 #else
-    long index = pCurr->m_index;
-    assert(index < m_count);
+  long index = pCurr->m_index;
+  assert(index < m_count);
 
-    CuePoint* const* const pp = m_cue_points;
-    assert(pp);
-    assert(pp[index] == pCurr);
+  CuePoint* const* const pp = m_cue_points;
+  assert(pp);
+  assert(pp[index] == pCurr);
 
-    ++index;
+  ++index;
 
-    if (index >= m_count)
-        return NULL;
+  if (index >= m_count)
+    return NULL;
 
-    CuePoint* const pNext = pp[index];
-    assert(pNext);
-    assert(pNext->GetTimeCode() >= 0);
+  CuePoint* const pNext = pp[index];
+  assert(pNext);
+  assert(pNext->GetTimeCode() >= 0);
 #endif
 
-    return pNext;
+  return pNext;
 }
 
+const BlockEntry* Cues::GetBlock(const CuePoint* pCP,
+                                 const CuePoint::TrackPosition* pTP) const {
+  if (pCP == NULL)
+    return NULL;
 
-const BlockEntry* Cues::GetBlock(
-    const CuePoint* pCP,
-    const CuePoint::TrackPosition* pTP) const
-{
-    if (pCP == NULL)
-        return NULL;
+  if (pTP == NULL)
+    return NULL;
 
-    if (pTP == NULL)
-        return NULL;
-
-    return m_pSegment->GetBlock(*pCP, *pTP);
+  return m_pSegment->GetBlock(*pCP, *pTP);
 }
 
+const BlockEntry* Segment::GetBlock(const CuePoint& cp,
+                                    const CuePoint::TrackPosition& tp) {
+  Cluster** const ii = m_clusters;
+  Cluster** i = ii;
 
-const BlockEntry* Segment::GetBlock(
-    const CuePoint& cp,
-    const CuePoint::TrackPosition& tp)
-{
-    Cluster** const ii = m_clusters;
-    Cluster** i = ii;
+  const long count = m_clusterCount + m_clusterPreloadCount;
 
-    const long count = m_clusterCount + m_clusterPreloadCount;
+  Cluster** const jj = ii + count;
+  Cluster** j = jj;
 
-    Cluster** const jj = ii + count;
-    Cluster** j = jj;
+  while (i < j) {
+    // INVARIANT:
+    //[ii, i) < pTP->m_pos
+    //[i, j) ?
+    //[j, jj)  > pTP->m_pos
 
-    while (i < j)
-    {
-        //INVARIANT:
-        //[ii, i) < pTP->m_pos
-        //[i, j) ?
-        //[j, jj)  > pTP->m_pos
+    Cluster** const k = i + (j - i) / 2;
+    assert(k < jj);
 
-        Cluster** const k = i + (j - i) / 2;
-        assert(k < jj);
-
-        Cluster* const pCluster = *k;
-        assert(pCluster);
-
-        //const long long pos_ = pCluster->m_pos;
-        //assert(pos_);
-        //const long long pos = pos_ * ((pos_ < 0) ? -1 : 1);
-
-        const long long pos = pCluster->GetPosition();
-        assert(pos >= 0);
-
-        if (pos < tp.m_pos)
-            i = k + 1;
-        else if (pos > tp.m_pos)
-            j = k;
-        else
-            return pCluster->GetEntry(cp, tp);
-    }
-
-    assert(i == j);
-    //assert(Cluster::HasBlockEntries(this, tp.m_pos));
-
-    Cluster* const pCluster = Cluster::Create(this, -1, tp.m_pos); //, -1);
+    Cluster* const pCluster = *k;
     assert(pCluster);
 
-    const ptrdiff_t idx = i - m_clusters;
+    // const long long pos_ = pCluster->m_pos;
+    // assert(pos_);
+    // const long long pos = pos_ * ((pos_ < 0) ? -1 : 1);
 
-    PreloadCluster(pCluster, idx);
-    assert(m_clusters);
-    assert(m_clusterPreloadCount > 0);
-    assert(m_clusters[idx] == pCluster);
+    const long long pos = pCluster->GetPosition();
+    assert(pos >= 0);
 
-    return pCluster->GetEntry(cp, tp);
+    if (pos < tp.m_pos)
+      i = k + 1;
+    else if (pos > tp.m_pos)
+      j = k;
+    else
+      return pCluster->GetEntry(cp, tp);
+  }
+
+  assert(i == j);
+  // assert(Cluster::HasBlockEntries(this, tp.m_pos));
+
+  Cluster* const pCluster = Cluster::Create(this, -1, tp.m_pos);  //, -1);
+  assert(pCluster);
+
+  const ptrdiff_t idx = i - m_clusters;
+
+  PreloadCluster(pCluster, idx);
+  assert(m_clusters);
+  assert(m_clusterPreloadCount > 0);
+  assert(m_clusters[idx] == pCluster);
+
+  return pCluster->GetEntry(cp, tp);
 }
 
+const Cluster* Segment::FindOrPreloadCluster(long long requested_pos) {
+  if (requested_pos < 0)
+    return 0;
 
-const Cluster* Segment::FindOrPreloadCluster(long long requested_pos)
-{
-    if (requested_pos < 0)
-        return 0;
+  Cluster** const ii = m_clusters;
+  Cluster** i = ii;
 
-    Cluster** const ii = m_clusters;
-    Cluster** i = ii;
+  const long count = m_clusterCount + m_clusterPreloadCount;
 
-    const long count = m_clusterCount + m_clusterPreloadCount;
+  Cluster** const jj = ii + count;
+  Cluster** j = jj;
 
-    Cluster** const jj = ii + count;
-    Cluster** j = jj;
+  while (i < j) {
+    // INVARIANT:
+    //[ii, i) < pTP->m_pos
+    //[i, j) ?
+    //[j, jj)  > pTP->m_pos
 
-    while (i < j)
-    {
-        //INVARIANT:
-        //[ii, i) < pTP->m_pos
-        //[i, j) ?
-        //[j, jj)  > pTP->m_pos
+    Cluster** const k = i + (j - i) / 2;
+    assert(k < jj);
 
-        Cluster** const k = i + (j - i) / 2;
-        assert(k < jj);
-
-        Cluster* const pCluster = *k;
-        assert(pCluster);
-
-        //const long long pos_ = pCluster->m_pos;
-        //assert(pos_);
-        //const long long pos = pos_ * ((pos_ < 0) ? -1 : 1);
-
-        const long long pos = pCluster->GetPosition();
-        assert(pos >= 0);
-
-        if (pos < requested_pos)
-            i = k + 1;
-        else if (pos > requested_pos)
-            j = k;
-        else
-            return pCluster;
-    }
-
-    assert(i == j);
-    //assert(Cluster::HasBlockEntries(this, tp.m_pos));
-
-    Cluster* const pCluster = Cluster::Create(
-                                this,
-                                -1,
-                                requested_pos);
-                                //-1);
+    Cluster* const pCluster = *k;
     assert(pCluster);
 
-    const ptrdiff_t idx = i - m_clusters;
+    // const long long pos_ = pCluster->m_pos;
+    // assert(pos_);
+    // const long long pos = pos_ * ((pos_ < 0) ? -1 : 1);
 
-    PreloadCluster(pCluster, idx);
-    assert(m_clusters);
-    assert(m_clusterPreloadCount > 0);
-    assert(m_clusters[idx] == pCluster);
+    const long long pos = pCluster->GetPosition();
+    assert(pos >= 0);
 
-    return pCluster;
+    if (pos < requested_pos)
+      i = k + 1;
+    else if (pos > requested_pos)
+      j = k;
+    else
+      return pCluster;
+  }
+
+  assert(i == j);
+  // assert(Cluster::HasBlockEntries(this, tp.m_pos));
+
+  Cluster* const pCluster = Cluster::Create(this, -1, requested_pos);
+  //-1);
+  assert(pCluster);
+
+  const ptrdiff_t idx = i - m_clusters;
+
+  PreloadCluster(pCluster, idx);
+  assert(m_clusters);
+  assert(m_clusterPreloadCount > 0);
+  assert(m_clusters[idx] == pCluster);
+
+  return pCluster;
 }
 
-
-CuePoint::CuePoint(long idx, long long pos) :
-    m_element_start(0),
-    m_element_size(0),
-    m_index(idx),
-    m_timecode(-1 * pos),
-    m_track_positions(NULL),
-    m_track_positions_count(0)
-{
-    assert(pos > 0);
+CuePoint::CuePoint(long idx, long long pos)
+    : m_element_start(0),
+      m_element_size(0),
+      m_index(idx),
+      m_timecode(-1 * pos),
+      m_track_positions(NULL),
+      m_track_positions_count(0) {
+  assert(pos > 0);
 }
 
+CuePoint::~CuePoint() { delete[] m_track_positions; }
 
-CuePoint::~CuePoint()
-{
-    delete[] m_track_positions;
-}
+void CuePoint::Load(IMkvReader* pReader) {
+  // odbgstream os;
+  // os << "CuePoint::Load(begin): timecode=" << m_timecode << endl;
 
+  if (m_timecode >= 0)  // already loaded
+    return;
 
-void CuePoint::Load(IMkvReader* pReader)
-{
-    //odbgstream os;
-    //os << "CuePoint::Load(begin): timecode=" << m_timecode << endl;
+  assert(m_track_positions == NULL);
+  assert(m_track_positions_count == 0);
 
-    if (m_timecode >= 0)  //already loaded
-        return;
+  long long pos_ = -m_timecode;
+  const long long element_start = pos_;
 
-    assert(m_track_positions == NULL);
-    assert(m_track_positions_count == 0);
+  long long stop;
 
-    long long pos_ = -m_timecode;
-    const long long element_start = pos_;
+  {
+    long len;
 
-    long long stop;
+    const long long id = ReadUInt(pReader, pos_, len);
+    assert(id == 0x3B);  // CuePoint ID
+    if (id != 0x3B)
+      return;
 
-    {
-        long len;
+    pos_ += len;  // consume ID
 
-        const long long id = ReadUInt(pReader, pos_, len);
-        assert(id == 0x3B);  //CuePoint ID
-        if (id != 0x3B)
-            return;
+    const long long size = ReadUInt(pReader, pos_, len);
+    assert(size >= 0);
 
-        pos_ += len;  //consume ID
+    pos_ += len;  // consume Size field
+    // pos_ now points to start of payload
 
-        const long long size = ReadUInt(pReader, pos_, len);
-        assert(size >= 0);
+    stop = pos_ + size;
+  }
 
-        pos_ += len;  //consume Size field
-        //pos_ now points to start of payload
+  const long long element_size = stop - element_start;
 
-        stop = pos_ + size;
+  long long pos = pos_;
+
+  // First count number of track positions
+
+  while (pos < stop) {
+    long len;
+
+    const long long id = ReadUInt(pReader, pos, len);
+    assert(id >= 0);  // TODO
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume ID
+
+    const long long size = ReadUInt(pReader, pos, len);
+    assert(size >= 0);
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume Size field
+    assert((pos + size) <= stop);
+
+    if (id == 0x33)  // CueTime ID
+      m_timecode = UnserializeUInt(pReader, pos, size);
+
+    else if (id == 0x37)  // CueTrackPosition(s) ID
+      ++m_track_positions_count;
+
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
+
+  assert(m_timecode >= 0);
+  assert(m_track_positions_count > 0);
+
+  // os << "CuePoint::Load(cont'd): idpos=" << idpos
+  //   << " timecode=" << m_timecode
+  //   << endl;
+
+  m_track_positions = new TrackPosition[m_track_positions_count];
+
+  // Now parse track positions
+
+  TrackPosition* p = m_track_positions;
+  pos = pos_;
+
+  while (pos < stop) {
+    long len;
+
+    const long long id = ReadUInt(pReader, pos, len);
+    assert(id >= 0);  // TODO
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume ID
+
+    const long long size = ReadUInt(pReader, pos, len);
+    assert(size >= 0);
+    assert((pos + len) <= stop);
+
+    pos += len;  // consume Size field
+    assert((pos + size) <= stop);
+
+    if (id == 0x37) {  // CueTrackPosition(s) ID
+      TrackPosition& tp = *p++;
+      tp.Parse(pReader, pos, size);
     }
 
-    const long long element_size = stop - element_start;
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
 
-    long long pos = pos_;
+  assert(size_t(p - m_track_positions) == m_track_positions_count);
 
-    //First count number of track positions
-
-    while (pos < stop)
-    {
-        long len;
-
-        const long long id = ReadUInt(pReader, pos, len);
-        assert(id >= 0);  //TODO
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume ID
-
-        const long long size = ReadUInt(pReader, pos, len);
-        assert(size >= 0);
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume Size field
-        assert((pos + size) <= stop);
-
-        if (id == 0x33)  //CueTime ID
-            m_timecode = UnserializeUInt(pReader, pos, size);
-
-        else if (id == 0x37) //CueTrackPosition(s) ID
-            ++m_track_positions_count;
-
-        pos += size;  //consume payload
-        assert(pos <= stop);
-    }
-
-    assert(m_timecode >= 0);
-    assert(m_track_positions_count > 0);
-
-    //os << "CuePoint::Load(cont'd): idpos=" << idpos
-    //   << " timecode=" << m_timecode
-    //   << endl;
-
-    m_track_positions = new TrackPosition[m_track_positions_count];
-
-    //Now parse track positions
-
-    TrackPosition* p = m_track_positions;
-    pos = pos_;
-
-    while (pos < stop)
-    {
-        long len;
-
-        const long long id = ReadUInt(pReader, pos, len);
-        assert(id >= 0);  //TODO
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume ID
-
-        const long long size = ReadUInt(pReader, pos, len);
-        assert(size >= 0);
-        assert((pos + len) <= stop);
-
-        pos += len;  //consume Size field
-        assert((pos + size) <= stop);
-
-        if (id == 0x37) //CueTrackPosition(s) ID
-        {
-            TrackPosition& tp = *p++;
-            tp.Parse(pReader, pos, size);
-        }
-
-        pos += size;  //consume payload
-        assert(pos <= stop);
-    }
-
-    assert(size_t(p - m_track_positions) == m_track_positions_count);
-
-    m_element_start = element_start;
-    m_element_size = element_size;
+  m_element_start = element_start;
+  m_element_size = element_size;
 }
 
+void CuePoint::TrackPosition::Parse(IMkvReader* pReader, long long start_,
+                                    long long size_) {
+  const long long stop = start_ + size_;
+  long long pos = start_;
 
+  m_track = -1;
+  m_pos = -1;
+  m_block = 1;  // default
 
-void CuePoint::TrackPosition::Parse(
-    IMkvReader* pReader,
-    long long start_,
-    long long size_)
-{
-    const long long stop = start_ + size_;
-    long long pos = start_;
+  while (pos < stop) {
+    long len;
 
-    m_track = -1;
-    m_pos = -1;
-    m_block = 1;  //default
+    const long long id = ReadUInt(pReader, pos, len);
+    assert(id >= 0);  // TODO
+    assert((pos + len) <= stop);
 
-    while (pos < stop)
-    {
-        long len;
+    pos += len;  // consume ID
 
-        const long long id = ReadUInt(pReader, pos, len);
-        assert(id >= 0);  //TODO
-        assert((pos + len) <= stop);
+    const long long size = ReadUInt(pReader, pos, len);
+    assert(size >= 0);
+    assert((pos + len) <= stop);
 
-        pos += len;  //consume ID
+    pos += len;  // consume Size field
+    assert((pos + size) <= stop);
 
-        const long long size = ReadUInt(pReader, pos, len);
-        assert(size >= 0);
-        assert((pos + len) <= stop);
+    if (id == 0x77)  // CueTrack ID
+      m_track = UnserializeUInt(pReader, pos, size);
 
-        pos += len;  //consume Size field
-        assert((pos + size) <= stop);
+    else if (id == 0x71)  // CueClusterPos ID
+      m_pos = UnserializeUInt(pReader, pos, size);
 
-        if (id == 0x77)  //CueTrack ID
-            m_track = UnserializeUInt(pReader, pos, size);
+    else if (id == 0x1378)  // CueBlockNumber
+      m_block = UnserializeUInt(pReader, pos, size);
 
-        else if (id == 0x71)  //CueClusterPos ID
-            m_pos = UnserializeUInt(pReader, pos, size);
+    pos += size;  // consume payload
+    assert(pos <= stop);
+  }
 
-        else if (id == 0x1378)  //CueBlockNumber
-            m_block = UnserializeUInt(pReader, pos, size);
-
-        pos += size;  //consume payload
-        assert(pos <= stop);
-    }
-
-    assert(m_pos >= 0);
-    assert(m_track > 0);
-    //assert(m_block > 0);
+  assert(m_pos >= 0);
+  assert(m_track > 0);
+  // assert(m_block > 0);
 }
 
+const CuePoint::TrackPosition* CuePoint::Find(const Track* pTrack) const {
+  assert(pTrack);
 
-const CuePoint::TrackPosition* CuePoint::Find(const Track* pTrack) const
-{
-    assert(pTrack);
+  const long long n = pTrack->GetNumber();
 
-    const long long n = pTrack->GetNumber();
+  const TrackPosition* i = m_track_positions;
+  const TrackPosition* const j = i + m_track_positions_count;
 
-    const TrackPosition* i = m_track_positions;
-    const TrackPosition* const j = i + m_track_positions_count;
+  while (i != j) {
+    const TrackPosition& p = *i++;
 
-    while (i != j)
-    {
-        const TrackPosition& p = *i++;
+    if (p.m_track == n)
+      return &p;
+  }
 
-        if (p.m_track == n)
-            return &p;
-    }
-
-    return NULL;  //no matching track number found
+  return NULL;  // no matching track number found
 }
 
+long long CuePoint::GetTimeCode() const { return m_timecode; }
 
-long long CuePoint::GetTimeCode() const
-{
-    return m_timecode;
+long long CuePoint::GetTime(const Segment* pSegment) const {
+  assert(pSegment);
+  assert(m_timecode >= 0);
+
+  const SegmentInfo* const pInfo = pSegment->GetInfo();
+  assert(pInfo);
+
+  const long long scale = pInfo->GetTimeCodeScale();
+  assert(scale >= 1);
+
+  const long long time = scale * m_timecode;
+
+  return time;
 }
 
-long long CuePoint::GetTime(const Segment* pSegment) const
-{
-    assert(pSegment);
-    assert(m_timecode >= 0);
-
-    const SegmentInfo* const pInfo = pSegment->GetInfo();
-    assert(pInfo);
-
-    const long long scale = pInfo->GetTimeCodeScale();
-    assert(scale >= 1);
-
-    const long long time = scale * m_timecode;
-
-    return time;
-}
-
-
 #if 0
 long long Segment::Unparsed() const
 {
@@ -3232,808 +2910,745 @@

     return result;
 }
 #else
-bool Segment::DoneParsing() const
-{
-    if (m_size < 0)
-    {
-        long long total, avail;
+bool Segment::DoneParsing() const {
+  if (m_size < 0) {
+    long long total, avail;
 
-        const int status = m_pReader->Length(&total, &avail);
+    const int status = m_pReader->Length(&total, &avail);
 
-        if (status < 0)  //error
-            return true;  //must assume done
+    if (status < 0)  // error
+      return true;  // must assume done
 
-        if (total < 0)
-            return false;  //assume live stream
+    if (total < 0)
+      return false;  // assume live stream
 
-        return (m_pos >= total);
-    }
+    return (m_pos >= total);
+  }
 
-    const long long stop = m_start + m_size;
+  const long long stop = m_start + m_size;
 
-    return (m_pos >= stop);
+  return (m_pos >= stop);
 }
 #endif
 
+const Cluster* Segment::GetFirst() const {
+  if ((m_clusters == NULL) || (m_clusterCount <= 0))
+    return &m_eos;
 
-const Cluster* Segment::GetFirst() const
-{
-    if ((m_clusters == NULL) || (m_clusterCount <= 0))
-       return &m_eos;
+  Cluster* const pCluster = m_clusters[0];
+  assert(pCluster);
 
-    Cluster* const pCluster = m_clusters[0];
-    assert(pCluster);
-
-    return pCluster;
+  return pCluster;
 }
 
+const Cluster* Segment::GetLast() const {
+  if ((m_clusters == NULL) || (m_clusterCount <= 0))
+    return &m_eos;
 
-const Cluster* Segment::GetLast() const
-{
-    if ((m_clusters == NULL) || (m_clusterCount <= 0))
-        return &m_eos;
+  const long idx = m_clusterCount - 1;
 
-    const long idx = m_clusterCount - 1;
+  Cluster* const pCluster = m_clusters[idx];
+  assert(pCluster);
 
-    Cluster* const pCluster = m_clusters[idx];
-    assert(pCluster);
-
-    return pCluster;
+  return pCluster;
 }
 
+unsigned long Segment::GetCount() const { return m_clusterCount; }
 
-unsigned long Segment::GetCount() const
-{
-    return m_clusterCount;
-}
+const Cluster* Segment::GetNext(const Cluster* pCurr) {
+  assert(pCurr);
+  assert(pCurr != &m_eos);
+  assert(m_clusters);
 
+  long idx = pCurr->m_index;
 
-const Cluster* Segment::GetNext(const Cluster* pCurr)
-{
-    assert(pCurr);
-    assert(pCurr != &m_eos);
-    assert(m_clusters);
+  if (idx >= 0) {
+    assert(m_clusterCount > 0);
+    assert(idx < m_clusterCount);
+    assert(pCurr == m_clusters[idx]);
 
-    long idx =  pCurr->m_index;
+    ++idx;
 
-    if (idx >= 0)
-    {
-        assert(m_clusterCount > 0);
-        assert(idx < m_clusterCount);
-        assert(pCurr == m_clusters[idx]);
+    if (idx >= m_clusterCount)
+      return &m_eos;  // caller will LoadCluster as desired
 
-        ++idx;
-
-        if (idx >= m_clusterCount)
-            return &m_eos;  //caller will LoadCluster as desired
-
-        Cluster* const pNext = m_clusters[idx];
-        assert(pNext);
-        assert(pNext->m_index >= 0);
-        assert(pNext->m_index == idx);
-
-        return pNext;
-    }
-
-    assert(m_clusterPreloadCount > 0);
-
-    long long pos = pCurr->m_element_start;
-
-    assert(m_size >= 0);  //TODO
-    const long long stop = m_start + m_size;  //end of segment
-
-    {
-        long len;
-
-        long long result = GetUIntLength(m_pReader, pos, len);
-        assert(result == 0);
-        assert((pos + len) <= stop);  //TODO
-        if (result != 0)
-            return NULL;
-
[... patch truncado ...]
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
