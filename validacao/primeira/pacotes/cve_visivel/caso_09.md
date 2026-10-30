# Pacote de anotacao — caso 09

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

# Evidencia do caso 09

## Identificacao

- projeto: Chrome
- CVE: CVE-2012-5157
- CWE atribuida pelo BigVul: CWE-119
- commit: `7f0126ff011142c8619b10a6e64d04d1745c503a`
- URL do commit: https://github.com/chromium/chromium/commit/7f0126ff011142c8619b10a6e64d04d1745c503a
- arquivo da funcao marcada: `third_party/WebKit/Source/core/page/PageSerializer.cpp`

## Mensagem do commit

> Revert 162155 "This review merges the two existing page serializ..."
> 
> Change r162155 broke the world even though it was landed using the CQ.
> 
> > This review merges the two existing page serializers, WebPageSerializerImpl and
> > PageSerializer, into one, PageSerializer. In addition to this it moves all
> > the old tests from WebPageNewSerializerTest and WebPageSerializerTest to the
> > PageSerializerTest structure and splits out one test for MHTML into a new
> > MHTMLTest file.
> > 
> > Saving as 'Webpage, Complete', 'Webpage, HTML Only' and as MHTML when the
> > 'Save Page as MHTML' flag is enabled now uses the same code, and should thus
> > have the same feature set. Meaning that both modes now should be a bit better.
> > 
> > Detailed list of changes:
> > 
> > - PageSerializerTest: Prepare for more DTD test
> > - PageSerializerTest: Remove now unneccesary input image test
> > - PageSerializerTest: Remove unused WebPageSerializer/Impl code
> > - PageSerializerTest: Move data URI morph test
> > - PageSerializerTest: Move data URI test
> > - PageSerializerTest: Move namespace test
> > - PageSerializerTest: Move SVG Image test
> > - MHTMLTest: Move MHTML specific test to own test file
> > - PageSerializerTest: Delete duplicate XML header test
> > - PageSerializerTest: Move blank frame test
> > - PageSerializerTest: Move CSS test
> > - PageSerializerTest: Add frameset/frame test
> > - PageSerializerTest: Move old iframe test
> > - PageSerializerTest: Move old elements test
> > - Use PageSerizer for saving web pages
> > - PageSerializerTest: Test for rewriting links
> > - PageSerializer: Add rewrite link accumulator
> > - PageSerializer: Serialize images in iframes/frames src
> > - PageSerializer: XHTML fix for meta tags
> > - PageSerializer: Add presentation CSS
> > - PageSerializer: Rename out parameter
> > 
> > BUG=
> > R=abarth@chromium.org
> > 
> > Review URL: https://codereview.chromium.org/68613003
> 
> TBR=tiger@opera.com
> 
> Review URL: https://codereview.chromium.org/73673003
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@162156 bbb929c8-8fbe-4397-9dbb-9b2b20218538

## Resumo da CVE

> Google Chrome before 24.0.1312.52 does not properly handle image data in PDF documents, which allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted document.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -10,19 +10,15 @@
          return;
      }
  
-    if (document->isImageDocument()) {
-        ImageDocument* imageDocument = toImageDocument(document);
-        addImageToResources(imageDocument->cachedImage(), imageDocument->imageElement()->renderer(), url);
+     Vector<Node*> nodes;
+    SerializerMarkupAccumulator accumulator(this, document, &nodes);
+     WTF::TextEncoding textEncoding(document->charset());
+    CString data;
+    if (!textEncoding.isValid()) {
+        // FIXME: iframes used as images trigger this. We should deal with them correctly.
         return;
     }
-     Vector<Node*> nodes;
-    OwnPtr<SerializerMarkupAccumulator> accumulator;
-    if (m_URLs)
-        accumulator = adoptPtr(new LinkChangeSerializerMarkupAccumulator(this, document, &nodes, m_URLs, m_directory));
-    else
-        accumulator = adoptPtr(new SerializerMarkupAccumulator(this, document, &nodes));
-    String text = accumulator->serializeNodes(document, IncludeNode);
-     WTF::TextEncoding textEncoding(document->charset());
+    String text = accumulator.serializeNodes(document, IncludeNode);
      CString frameHTML = textEncoding.normalizeAndEncode(text, WTF::EntitiesForUnencodables);
      m_resources->append(SerializedResource(url, document->suggestedMIMEType(), SharedBuffer::create(frameHTML.data(), frameHTML.length())));
      m_resourceURLs.add(url);
@@ -33,10 +29,8 @@
             continue;
  
          Element* element = toElement(node);
-        if (element->isStyledElement()) {
+        if (element->isStyledElement())
              retrieveResourcesForProperties(element->inlineStyle(), document);
-            retrieveResourcesForProperties(element->presentationAttributeStyle(), document);
-        }
  
          if (element->hasTagName(HTMLNames::imgTag)) {
              HTMLImageElement* imageElement = toHTMLImageElement(element);
```

## Corpo completo da funcao antes da correcao

```c
void PageSerializer::serializeFrame(Frame* frame)
{
    Document* document = frame->document();
    KURL url = document->url();
    if (!url.isValid() || url.isBlankURL()) {
        url = urlForBlankFrame(frame);
    }

    if (m_resourceURLs.contains(url)) {
         return;
     }
 
    if (document->isImageDocument()) {
        ImageDocument* imageDocument = toImageDocument(document);
        addImageToResources(imageDocument->cachedImage(), imageDocument->imageElement()->renderer(), url);
        return;
    }
     Vector<Node*> nodes;
    OwnPtr<SerializerMarkupAccumulator> accumulator;
    if (m_URLs)
        accumulator = adoptPtr(new LinkChangeSerializerMarkupAccumulator(this, document, &nodes, m_URLs, m_directory));
    else
        accumulator = adoptPtr(new SerializerMarkupAccumulator(this, document, &nodes));
    String text = accumulator->serializeNodes(document, IncludeNode);
     WTF::TextEncoding textEncoding(document->charset());
     CString frameHTML = textEncoding.normalizeAndEncode(text, WTF::EntitiesForUnencodables);
     m_resources->append(SerializedResource(url, document->suggestedMIMEType(), SharedBuffer::create(frameHTML.data(), frameHTML.length())));
     m_resourceURLs.add(url);

    for (Vector<Node*>::iterator iter = nodes.begin(); iter != nodes.end(); ++iter) {
        Node* node = *iter;
        if (!node->isElementNode())
            continue;
 
         Element* element = toElement(node);
        if (element->isStyledElement()) {
             retrieveResourcesForProperties(element->inlineStyle(), document);
            retrieveResourcesForProperties(element->presentationAttributeStyle(), document);
        }
 
         if (element->hasTagName(HTMLNames::imgTag)) {
             HTMLImageElement* imageElement = toHTMLImageElement(element);
            KURL url = document->completeURL(imageElement->getAttribute(HTMLNames::srcAttr));
            ImageResource* cachedImage = imageElement->cachedImage();
            addImageToResources(cachedImage, imageElement->renderer(), url);
        } else if (element->hasTagName(HTMLNames::inputTag)) {
            HTMLInputElement* inputElement = toHTMLInputElement(element);
            if (inputElement->isImageButton() && inputElement->hasImageLoader()) {
                KURL url = inputElement->src();
                ImageResource* cachedImage = inputElement->imageLoader()->image();
                addImageToResources(cachedImage, inputElement->renderer(), url);
            }
        } else if (element->hasTagName(HTMLNames::linkTag)) {
            HTMLLinkElement* linkElement = toHTMLLinkElement(element);
            if (CSSStyleSheet* sheet = linkElement->sheet()) {
                KURL url = document->completeURL(linkElement->getAttribute(HTMLNames::hrefAttr));
                serializeCSSStyleSheet(sheet, url);
                ASSERT(m_resourceURLs.contains(url));
            }
        } else if (element->hasTagName(HTMLNames::styleTag)) {
            HTMLStyleElement* styleElement = toHTMLStyleElement(element);
            if (CSSStyleSheet* sheet = styleElement->sheet())
                serializeCSSStyleSheet(sheet, KURL());
        }
    }

    for (Frame* childFrame = frame->tree().firstChild(); childFrame; childFrame = childFrame->tree().nextSibling())
        serializeFrame(childFrame);
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **65**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/WebKit/Source/core/dom/Element.h` | modified | 2 | 1 |
| `third_party/WebKit/Source/core/editing/MarkupAccumulator.h` | modified | 1 | 1 |
| `third_party/WebKit/Source/core/page/PageSerializer.cpp` **(funcao marcada esta aqui)** | modified | 24 | 117 |
| `third_party/WebKit/Source/core/page/PageSerializer.h` | modified | 1 | 7 |
| `third_party/WebKit/Source/web/WebPageSerializer.cpp` | modified | 181 | 15 |
| `third_party/WebKit/Source/web/WebPageSerializerImpl.cpp` | added | 527 | 0 |
| `third_party/WebKit/Source/web/WebPageSerializerImpl.h` | added | 192 | 0 |
| `third_party/WebKit/Source/web/tests/MHTMLTest.cpp` | removed | 0 | 169 |
| `third_party/WebKit/Source/web/tests/PageSerializerTest.cpp` | modified | 14 | 276 |
| `third_party/WebKit/Source/web/tests/WebFrameTest.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/web/tests/WebPageNewSerializerTest.cpp` | added | 440 | 0 |
| `third_party/WebKit/Source/web/tests/WebPageSerializerTest.cpp` | added | 193 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/awesome.png` | added | 1 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/beautifull.css` | added | 1 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/embed_iframe.html` | renamed | 2 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/object_iframe.html` | renamed | 2 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/simple_iframe.html` | added | 14 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/simple_page.html` | added | 50 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserialization/top_frame.html` | added | 28 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/blank_frames.html` | renamed | 4 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/blue_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/css/image.png` | removed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/css_test_page.html` | renamed | 5 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/datauri/page_with_data.html` | removed | 0 | 10 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/dtd/dtd.html` | renamed | 2 | 2 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/elements/elements.html` | removed | 0 | 45 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/elements/image.png` | removed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/elements/style.css` | removed | 0 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/elements/text.txt` | removed | 0 | 1 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/image.png` | removed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames.html` | removed | 0 | 14 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_1.html` | removed | 0 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_3.html` | removed | 0 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_top.html` | removed | 0 | 7 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_iframe.html` | removed | 0 | 5 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/frames/top_frame.html` | removed | 0 | 21 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/green_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/green_rectangle.svg` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/iframe.html` | added | 9 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/iframe2.html` | added | 9 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/import_style_from_link.css` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/import_styles.css` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/input-image/button.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/input-image/input-image.html` | added | 25 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/link_styles.css` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/namespace_element.html` | renamed | 0 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/ol-dot.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/orange_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/page_with_data.html` | added | 9 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/page_with_morphing_data.html` | renamed | 3 | 3 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/page_with_svg_image.html` | added | 6 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/purple_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/red_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/rewritelinks/image.png` | removed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/rewritelinks/rewritelinks_base.html` | removed | 0 | 13 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/rewritelinks/rewritelinks_simple.html` | removed | 0 | 9 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/simple.xhtml` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/svg/page_with_svg_image.html` | removed | 0 | 9 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/top_frame.html` | added | 12 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/ul-dot.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/xmldecl/xmldecl.xml` | renamed | 0 | 0 |
| `third_party/WebKit/Source/web/tests/data/pageserializer/yellow_background.png` | added | 0 | 0 |
| `third_party/WebKit/Source/web/web.gypi` | modified | 6 | 1 |
| `third_party/WebKit/public/web/WebPageSerializer.h` | modified | 23 | 5 |
| `third_party/WebKit/public/web/WebPageSerializerClient.h` | modified | 2 | 2 |


### `third_party/WebKit/Source/core/page/PageSerializer.cpp`

```diff
@@ -53,7 +53,6 @@
 #include "core/html/HTMLInputElement.h"
 #include "core/html/HTMLLinkElement.h"
 #include "core/html/HTMLStyleElement.h"
-#include "core/html/ImageDocument.h"
 #include "core/html/parser/HTMLMetaCharsetParser.h"
 #include "core/frame/Frame.h"
 #include "core/page/Page.h"
@@ -106,11 +105,12 @@ class SerializerMarkupAccumulator : public WebCore::MarkupAccumulator {
     virtual ~SerializerMarkupAccumulator();
 
 protected:
-    virtual void appendText(StringBuilder&, Text*) OVERRIDE;
-    virtual void appendElement(StringBuilder&, Element*, Namespaces*) OVERRIDE;
-    virtual void appendCustomAttributes(StringBuilder&, Element*, Namespaces*) OVERRIDE;
-    virtual void appendEndTag(Node*) OVERRIDE;
+    virtual void appendText(StringBuilder& out, Text*);
+    virtual void appendElement(StringBuilder& out, Element*, Namespaces*);
+    virtual void appendCustomAttributes(StringBuilder& out, Element*, Namespaces*);
+    virtual void appendEndTag(Node*);
 
+private:
     PageSerializer* m_serializer;
     Document* m_document;
 };
@@ -126,32 +126,28 @@ SerializerMarkupAccumulator::~SerializerMarkupAccumulator()
 {
 }
 
-void SerializerMarkupAccumulator::appendText(StringBuilder& result, Text* text)
+void SerializerMarkupAccumulator::appendText(StringBuilder& out, Text* text)
 {
     Element* parent = text->parentElement();
     if (parent && !shouldIgnoreElement(parent))
-        MarkupAccumulator::appendText(result, text);
+        MarkupAccumulator::appendText(out, text);
 }
 
-void SerializerMarkupAccumulator::appendElement(StringBuilder& result, Element* element, Namespaces* namespaces)
+void SerializerMarkupAccumulator::appendElement(StringBuilder& out, Element* element, Namespaces* namespaces)
 {
     if (!shouldIgnoreElement(element))
-        MarkupAccumulator::appendElement(result, element, namespaces);
+        MarkupAccumulator::appendElement(out, element, namespaces);
 
-    // FIXME: Refactor MarkupAccumulator so it is easier to append an element like this, without special cases for XHTML
     if (element->hasTagName(HTMLNames::headTag)) {
-        result.appendLiteral("<meta charset=\"");
-        result.append(m_document->charset());
-        if (m_document->isXHTMLDocument())
-            result.appendLiteral("\" />");
-        else
-            result.appendLiteral("\">");
+        out.append("<meta charset=\"");
+        out.append(m_document->charset());
+        out.append("\">");
     }
 
     // FIXME: For object (plugins) tags and video tag we could replace them by an image of their current contents.
 }
 
-void SerializerMarkupAccumulator::appendCustomAttributes(StringBuilder& result, Element* element, Namespaces* namespaces)
+void SerializerMarkupAccumulator::appendCustomAttributes(StringBuilder& out, Element* element, Namespaces* namespaces)
 {
     if (!element->isFrameOwnerElement())
         return;
@@ -167,7 +163,7 @@ void SerializerMarkupAccumulator::appendCustomAttributes(StringBuilder& result,
 
     // We need to give a fake location to blank frames so they can be referenced by the serialized frame.
     url = m_serializer->urlForBlankFrame(frame);
-    appendAttribute(result, element, Attribute(frameOwnerURLAttributeName(*frameOwner), url.string()), namespaces);
+    appendAttribute(out, element, Attribute(frameOwnerURLAttributeName(*frameOwner), url.string()), namespaces);
 }
 
 void SerializerMarkupAccumulator::appendEndTag(Node* node)
@@ -176,89 +172,8 @@ void SerializerMarkupAccumulator::appendEndTag(Node* node)
         MarkupAccumulator::appendEndTag(node);
 }
 
-class LinkChangeSerializerMarkupAccumulator : public SerializerMarkupAccumulator {
-public:
-    LinkChangeSerializerMarkupAccumulator(PageSerializer*, Document*, Vector<Node*>*, LinkLocalPathMap*, String);
-
-protected:
-    virtual void appendElement(StringBuilder&, Element*, Namespaces*) OVERRIDE;
-    virtual void appendAttribute(StringBuilder&, Element*, const Attribute&, Namespaces*) OVERRIDE;
-
-private:
-    // m_replaceLinks include all pair of local resource path and corresponding original link.
-    LinkLocalPathMap* m_replaceLinks;
-    String m_directoryName;
-};
-
-LinkChangeSerializerMarkupAccumulator::LinkChangeSerializerMarkupAccumulator(PageSerializer* serializer, Document* document, Vector<Node*>* nodes, LinkLocalPathMap* links, String directoryName)
-    : SerializerMarkupAccumulator(serializer, document, nodes)
-    , m_replaceLinks(links)
-    , m_directoryName(directoryName)
-{
-}
-
-void LinkChangeSerializerMarkupAccumulator::appendElement(StringBuilder& result, Element* element, Namespaces* namespaces)
-{
-    // FIXME: We could move the uncommenting to appendOpenTag and appendCloseTag, or just remove it
-    if (element->hasTagName(HTMLNames::baseTag)) {
-        // Comment the BASE tag when serializing dom.
-        result.append("<!--");
-    } else if (element->hasTagName(HTMLNames::htmlTag)) {
-        // Add MOTW (Mark of the Web) declaration before html tag.
-        // See http://msdn2.microsoft.com/en-us/library/ms537628(VS.85).aspx.
-        result.append(String::format("\n<!-- saved from url=(%04d)%s -->\n",
-            static_cast<int>(m_document->url().string().utf8().length()),
-            m_document->url().string().utf8().data()));
-    }
-
-    SerializerMarkupAccumulator::appendElement(result, element, namespaces);
-
-    if (element->hasTagName(HTMLNames::baseTag)) {
-        // Comment the BASE tag when serializing dom.
-        result.appendLiteral("-->");
-
-        // FIXME: Refactor MarkupAccumulator so it is easier to append an element like this, without special cases for XHTML
-        // Append a new base tag declaration.
-        result.appendLiteral("<base href=\".\"");
-        if (!m_document->baseTarget().isEmpty()) {
-            result.appendLiteral(" target=\"");
-            result.append(m_document->baseTarget());
-            result.append('"');
-        }
-        if (m_document->isXHTMLDocument())
-            result.appendLiteral(" />");
-        else
-            result.appendLiteral(">");
-    }
-}
-void LinkChangeSerializerMarkupAccumulator::appendAttribute(StringBuilder& result, Element* element, const Attribute& attribute, Namespaces* namespaces)
-{
-    if (m_replaceLinks && element->isURLAttribute(attribute) && !element->isJavaScriptURLAttribute(attribute)) {
-
-        String completeURL = m_document->completeURL(attribute.value());
-
-        if (m_replaceLinks->contains(completeURL)) {
-            // FIXME: Refactor MarkupAccumulator so it is easier to append an attribute like this.
-            result.append(' ');
-            result.append(attribute.name().toString());
-            result.appendLiteral("=\"");
-            if (!m_directoryName.isEmpty()) {
-                result.appendLiteral("./");
-                result.append(m_directoryName);
-                result.append('/');
-            }
-            result.append(m_replaceLinks->get(completeURL));
-            result.appendLiteral("\"");
-            return;
-        }
-    }
-    MarkupAccumulator::appendAttribute(result, element, attribute, namespaces);
-}
-
-PageSerializer::PageSerializer(Vector<SerializedResource>* resources, LinkLocalPathMap* urls, String directory)
+PageSerializer::PageSerializer(Vector<SerializedResource>* resources)
     : m_resources(resources)
-    , m_URLs(urls)
-    , m_directory(directory)
     , m_blankFrameCounter(0)
 {
 }
@@ -284,21 +199,15 @@ void PageSerializer::serializeFrame(Frame* frame)
         return;
     }
 
-    // If frame is an image document, add the image and don't continue
-    if (document->isImageDocument()) {
-        ImageDocument* imageDocument = toImageDocument(document);
-        addImageToResources(imageDocument->cachedImage(), imageDocument->imageElement()->renderer(), url);
-        return;
-    }
-
     Vector<Node*> nodes;
-    OwnPtr<SerializerMarkupAccumulator> accumulator;
-    if (m_URLs)
-        accumulator = adoptPtr(new LinkChangeSerializerMarkupAccumulator(this, document, &nodes, m_URLs, m_directory));
-    else
-        accumulator = adoptPtr(new SerializerMarkupAccumulator(this, document, &nodes));
-    String text = accumulator->serializeNodes(document, IncludeNode);
+    SerializerMarkupAccumulator accumulator(this, document, &nodes);
     WTF::TextEncoding textEncoding(document->charset());
+    CString data;
+    if (!textEncoding.isValid()) {
+        // FIXME: iframes used as images trigger this. We should deal with them correctly.
+        return;
+    }
+    String text = accumulator.serializeNodes(document, IncludeNode);
     CString frameHTML = textEncoding.normalizeAndEncode(text, WTF::EntitiesForUnencodables);
     m_resources->append(SerializedResource(url, document->suggestedMIMEType(), SharedBuffer::create(frameHTML.data(), frameHTML.length())));
     m_resourceURLs.add(url);
@@ -310,10 +219,8 @@ void PageSerializer::serializeFrame(Frame* frame)
 
         Element* element = toElement(node);
         // We have to process in-line style as it might contain some resources (typically background images).
-        if (element->isStyledElement()) {
+        if (element->isStyledElement())
             retrieveResourcesForProperties(element->inlineStyle(), document);
-            retrieveResourcesForProperties(element->presentationAttributeStyle(), document);
-        }
 
         if (element->hasTagName(HTMLNames::imgTag)) {
             HTMLImageElement* imageElement = toHTMLImageElement(element);
@@ -404,7 +311,7 @@ void PageSerializer::addImageToResources(ImageResource* image, RenderObject* ima
     if (!shouldAddURL(url))
         return;
 
-    if (!image || !image->hasImage() || image->image() == Image::nullImage())
+    if (!image || image->image() == Image::nullImage())
         return;
 
     RefPtr<SharedBuffer> data = imageRenderer ? image->imageForRenderer(imageRenderer)->data() : 0;
```


### `third_party/WebKit/Source/core/dom/Element.h`

```diff
@@ -368,7 +368,6 @@ class Element : public ContainerNode {
     virtual void accessKeyAction(bool /*sendToAnyEvent*/) { }
 
     virtual bool isURLAttribute(const Attribute&) const { return false; }
-    bool isJavaScriptURLAttribute(const Attribute&) const;
     virtual bool isHTMLContentAttribute(const Attribute&) const { return false; }
 
     KURL getURLAttribute(const QualifiedName&) const;
@@ -669,6 +668,8 @@ class Element : public ContainerNode {
     void detachAttrNodeFromElementWithValue(Attr*, const AtomicString& value);
     void detachAttrNodeAtIndex(Attr*, size_t index);
 
+    bool isJavaScriptURLAttribute(const Attribute&) const;
+
     RefPtr<ElementData> m_elementData;
 };
 
```


### `third_party/WebKit/Source/core/editing/MarkupAccumulator.h`

```diff
@@ -97,7 +97,7 @@ class MarkupAccumulator {
     virtual void appendElement(StringBuilder&, Element*, Namespaces*);
     void appendOpenTag(StringBuilder&, Element*, Namespaces*);
     void appendCloseTag(StringBuilder&, Element*);
-    virtual void appendAttribute(StringBuilder&, Element*, const Attribute&, Namespaces*);
+    void appendAttribute(StringBuilder&, Element*, const Attribute&, Namespaces*);
     void appendCDATASection(StringBuilder&, const String&);
     void appendStartMarkup(StringBuilder&, const Node*, Namespaces*);
     bool shouldSelfClose(const Node*);
```


### `third_party/WebKit/Source/core/page/PageSerializer.h`

```diff
@@ -55,15 +55,11 @@ class StyleRuleFontFace;
 
 struct SerializedResource;
 
-// This hash map is used to map resource URL of original link to its local
-// file path.
-typedef HashMap<String, String> LinkLocalPathMap;
-
 // This class is used to serialize a page contents back to text (typically HTML).
 // It serializes all the page frames and retrieves resources such as images and CSS stylesheets.
 class PageSerializer {
 public:
-    PageSerializer(Vector<SerializedResource>*, LinkLocalPathMap* = 0, String directory = "");
+    explicit PageSerializer(Vector<SerializedResource>*);
 
     // Initiates the serialization of the frame's page. All serialized content and retrieved
     // resources are added to the Vector passed to the constructor. The first resource in that
@@ -91,8 +87,6 @@ class PageSerializer {
     Vector<SerializedResource>* m_resources;
     ListHashSet<KURL> m_resourceURLs;
     HashMap<Frame*, KURL> m_blankFrameURLs;
-    LinkLocalPathMap* m_URLs;
-    String m_directory;
     unsigned m_blankFrameCounter;
 };
 
```


### `third_party/WebKit/Source/web/WebPageSerializer.cpp`

```diff
@@ -35,6 +35,7 @@
 #include "WebFrame.h"
 #include "WebFrameImpl.h"
 #include "WebPageSerializerClient.h"
+#include "WebPageSerializerImpl.h"
 #include "WebView.h"
 #include "WebViewImpl.h"
 #include "core/dom/Document.h"
@@ -58,6 +59,126 @@
 
 using namespace WebCore;
 
+namespace {
+
+KURL getSubResourceURLFromElement(Element* element)
+{
+    ASSERT(element);
+    const QualifiedName* attributeName = 0;
+    if (element->hasTagName(HTMLNames::imgTag) || element->hasTagName(HTMLNames::scriptTag))
+        attributeName = &HTMLNames::srcAttr;
+    else if (element->hasTagName(HTMLNames::inputTag)) {
+        if (toHTMLInputElement(element)->isImageButton())
+            attributeName = &HTMLNames::srcAttr;
+    } else if (element->hasTagName(HTMLNames::bodyTag)
+        || isHTMLTableElement(element)
+        || element->hasTagName(HTMLNames::trTag)
+        || element->hasTagName(HTMLNames::tdTag))
+        attributeName = &HTMLNames::backgroundAttr;
+    else if (element->hasTagName(HTMLNames::blockquoteTag)
+             || element->hasTagName(HTMLNames::qTag)
+             || element->hasTagName(HTMLNames::delTag)
+             || element->hasTagName(HTMLNames::insTag))
+        attributeName = &HTMLNames::citeAttr;
+    else if (element->hasTagName(HTMLNames::linkTag)) {
+        // If the link element is not css, ignore it.
+        if (equalIgnoringCase(element->getAttribute(HTMLNames::typeAttr), "text/css")) {
+            // FIXME: Add support for extracting links of sub-resources which
+            // are inside style-sheet such as @import, @font-face, url(), etc.
+            attributeName = &HTMLNames::hrefAttr;
+        }
+    } else if (element->hasTagName(HTMLNames::objectTag))
+        attributeName = &HTMLNames::dataAttr;
+    else if (element->hasTagName(HTMLNames::embedTag))
+        attributeName = &HTMLNames::srcAttr;
+
+    if (!attributeName)
+        return KURL();
+
+    String value = element->getAttribute(*attributeName);
+    // Ignore javascript content.
+    if (value.isEmpty() || value.stripWhiteSpace().startsWith("javascript:", false))
+        return KURL();
+
+    return element->document().completeURL(value);
+}
+
+void retrieveResourcesForElement(Element* element,
+                                 Vector<Frame*>* visitedFrames,
+                                 Vector<Frame*>* framesToVisit,
+                                 Vector<KURL>* frameURLs,
+                                 Vector<KURL>* resourceURLs)
+{
+    // If the node is a frame, we'll process it later in retrieveResourcesForFrame.
+    if ((element->hasTagName(HTMLNames::iframeTag) || element->hasTagName(HTMLNames::frameTag)
+        || element->hasTagName(HTMLNames::objectTag) || element->hasTagName(HTMLNames::embedTag))
+            && element->isFrameOwnerElement()) {
+        if (Frame* frame = toHTMLFrameOwnerElement(element)->contentFrame()) {
+            if (!visitedFrames->contains(frame))
+                framesToVisit->append(frame);
+            return;
+        }
+    }
+
+    KURL url = getSubResourceURLFromElement(element);
+    if (url.isEmpty() || !url.isValid())
+        return; // No subresource for this node.
+
+    // Ignore URLs that have a non-standard protocols. Since the FTP protocol
+    // does no have a cache mechanism, we skip it as well.
+    if (!url.protocolIsInHTTPFamily() && !url.isLocalFile())
+        return;
+
+    if (!resourceURLs->contains(url))
+        resourceURLs->append(url);
+}
+
+void retrieveResourcesForFrame(Frame* frame,
+                               const blink::WebVector<blink::WebCString>& supportedSchemes,
+                               Vector<Frame*>* visitedFrames,
+                               Vector<Frame*>* framesToVisit,
+                               Vector<KURL>* frameURLs,
+                               Vector<KURL>* resourceURLs)
+{
+    KURL frameURL = frame->loader().documentLoader()->request().url();
+
+    // If the frame's URL is invalid, ignore it, it is not retrievable.
+    if (!frameURL.isValid())
+        return;
+
+    // Ignore frames from unsupported schemes.
+    bool isValidScheme = false;
+    for (size_t i = 0; i < supportedSchemes.size(); ++i) {
+        if (frameURL.protocolIs(static_cast<CString>(supportedSchemes[i]).data())) {
+            isValidScheme = true;
+            break;
+        }
+    }
+    if (!isValidScheme)
+        return;
+
+    // If we have already seen that frame, ignore it.
+    if (visitedFrames->contains(frame))
+        return;
+    visitedFrames->append(frame);
+    if (!frameURLs->contains(frameURL))
+        frameURLs->append(frameURL);
+
+    // Now get the resources associated with each node of the document.
+    RefPtr<HTMLCollection> allNodes = frame->document()->all();
+    for (unsigned i = 0; i < allNodes->length(); ++i) {
+        Node* node = allNodes->item(i);
+        // We are only interested in HTML resources.
+        if (!node->isElementNode())
+            continue;
+        retrieveResourcesForElement(toElement(node),
+                                    visitedFrames, framesToVisit,
+                                    frameURLs, resourceURLs);
+    }
+}
+
+} // namespace
+
 namespace blink {
 
 void WebPageSerializer::serialize(WebView* view, WebVector<WebPageSerializer::Resource>* resourcesParam)
@@ -109,27 +230,72 @@ bool WebPageSerializer::serialize(WebFrame* frame,
                                   const WebVector<WebString>& localPaths,
                                   const WebString& localDirectoryName)
 {
-    ASSERT(frame);
-    ASSERT(client);
-    ASSERT(links.size() == localPaths.size());
+    WebPageSerializerImpl serializerImpl(
+        frame, recursive, client, links, localPaths, localDirectoryName);
+    return serializerImpl.serialize();
+}
 
-    LinkLocalPathMap m_localLinks;
+bool WebPageSerializer::retrieveAllResources(WebView* view,
+                                             const WebVector<WebCString>& supportedSchemes,
+                                             WebVector<WebURL>* resourceURLs,
+                                             WebVector<WebURL>* frameURLs) {
+    WebFrameImpl* mainFrame = toWebFrameImpl(view->mainFrame());
+    if (!mainFrame)
+        return false;
 
-    for (size_t i = 0; i < links.size(); i++) {
-        KURL url = links[i];
-        ASSERT(!m_localLinks.contains(url.string()));
-        m_localLinks.set(url.string(), localPaths[i]);
-    }
+    Vector<Frame*> framesToVisit;
+    Vector<Frame*> visitedFrames;
+    Vector<KURL> frameKURLs;
+    Vector<KURL> resourceKURLs;
 
-    Vector<SerializedResource> resources;
-    PageSerializer serializer(&resources, &m_localLinks, localDirectoryName);
-    serializer.serialize(toWebViewImpl(frame->view())->page());
+    // Let's retrieve the resources from every frame in this page.
+    framesToVisit.append(mainFrame->frame());
+    while (!framesToVisit.isEmpty()) {
+        Frame* frame = framesToVisit[0];
+        framesToVisit.remove(0);
+        retrieveResourcesForFrame(frame, supportedSchemes,
+                                  &visitedFrames, &framesToVisit,
+                                  &frameKURLs, &resourceKURLs);
+    }
 
-    for (Vector<SerializedResource>::const_iterator iter = resources.begin(); iter != resources.end(); ++iter) {
-        client->didSerializeDataForFrame(iter->url, WebCString(iter->data->data(), iter->data->size()), WebPageSerializerClient::CurrentFrameIsFinished);
+    // Converts the results to WebURLs.
+    WebVector<WebURL> resultResourceURLs(resourceKURLs.size());
+    for (size_t i = 0; i < resourceKURLs.size(); ++i) {
+        resultResourceURLs[i] = resourceKURLs[i];
+        // A frame's src can point to the same URL as another resource, keep the
+        // resource URL only in such cases.
+        size_t index = frameKURLs.find(resourceKURLs[i]);
+        if (index != kNotFound)
+            frameKURLs.remove(index);
     }
-    client->didSerializeDataForFrame(KURL(), WebCString("", 0), WebPageSerializerClient::AllFramesAreFinished);
+    *resourceURLs = resultResourceURLs;
+    WebVector<WebURL> resultFrameURLs(frameKURLs.size());
+    for (size_t i = 0; i < frameKURLs.size(); ++i)
+        resultFrameURLs[i] = frameKURLs[i];
+    *frameURLs = resultFrameURLs;
+
     return true;
 }
 
+WebString WebPageSerializer::generateMetaCharsetDeclaration(const WebString& charset)
+{
+    String charsetString = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=" + static_cast<const String&>(charset) + "\">";
+    return charsetString;
+}
+
+WebString WebPageSerializer::generateMarkOfTheWebDeclaration(const WebURL& url)
+{
+    return String::format("\n<!-- saved from url=(%04d)%s -->\n",
+                          static_cast<int>(url.spec().length()),
+                          url.spec().data());
+}
+
+WebString WebPageSerializer::generateBaseTagDeclaration(const WebString& baseTarget)
+{
+    if (baseTarget.isEmpty())
+        return String("<base href=\".\">");
+    String baseString = "<base href=\".\" target=\"" + static_cast<const String&>(baseTarget) + "\">";
+    return baseString;
+}
+
 } // namespace blink
```


### `third_party/WebKit/Source/web/WebPageSerializerImpl.cpp`

```diff
@@ -0,0 +1,527 @@
+/*
+ * Copyright (C) 2009 Google Inc. All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are
+ * met:
+ *
+ *     * Redistributions of source code must retain the above copyright
+ * notice, this list of conditions and the following disclaimer.
+ *     * Redistributions in binary form must reproduce the above
+ * copyright notice, this list of conditions and the following disclaimer
+ * in the documentation and/or other materials provided with the
+ * distribution.
+ *     * Neither the name of Google Inc. nor the names of its
+ * contributors may be used to endorse or promote products derived from
+ * this software without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+ * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+ * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+ * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+ * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+ * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+ * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+ * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+ * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+ */
+
+// How we handle the base tag better.
+// Current status:
+// At now the normal way we use to handling base tag is
+// a) For those links which have corresponding local saved files, such as
+// savable CSS, JavaScript files, they will be written to relative URLs which
+// point to local saved file. Why those links can not be resolved as absolute
+// file URLs, because if they are resolved as absolute URLs, after moving the
+// file location from one directory to another directory, the file URLs will
+// be dead links.
+// b) For those links which have not corresponding local saved files, such as
+// links in A, AREA tags, they will be resolved as absolute URLs.
+// c) We comment all base tags when serialzing DOM for the page.
+// FireFox also uses above way to handle base tag.
+//
+// Problem:
+// This way can not handle the following situation:
+// the base tag is written by JavaScript.
+// For example. The page "www.yahoo.com" use
+// "document.write('<base href="http://www.yahoo.com/"...');" to setup base URL
+// of page when loading page. So when saving page as completed-HTML, we assume
+// that we save "www.yahoo.com" to "c:\yahoo.htm". After then we load the saved
+// completed-HTML page, then the JavaScript will insert a base tag
+// <base href="http://www.yahoo.com/"...> to DOM, so all URLs which point to
+// local saved resource files will be resolved as
+// "http://www.yahoo.com/yahoo_files/...", which will cause all saved  resource
+// files can not be loaded correctly. Also the page will be rendered ugly since
+// all saved sub-resource files (such as CSS, JavaScript files) and sub-frame
+// files can not be fetched.
+// Now FireFox, IE and WebKit based Browser all have this problem.
+//
+// Solution:
+// My solution is that we comment old base tag and write new base tag:
+// <base href="." ...> after the previous commented base tag. In WebKit, it
+// always uses the latest "href" attribute of base tag to set document's base
+// URL. Based on this behavior, when we encounter a base tag, we comment it and
+// write a new base tag <base href="."> after the previous commented base tag.
+// The new added base tag can help engine to locate correct base URL for
+// correctly loading local saved resource files. Also I think we need to inherit
+// the base target value from document object when appending new base tag.
+// If there are multiple base tags in original document, we will comment all old
+// base tags and append new base tag after each old base tag because we do not
+// know those old base tags are original content or added by JavaScript. If
+// they are added by JavaScript, it means when loading saved page, the script(s)
+// will still insert base tag(s) to DOM, so the new added base tag(s) can
+// override the incorrect base URL and make sure we alway load correct local
+// saved resource files.
+
+#include "config.h"
+#include "WebPageSerializerImpl.h"
+
+#include "DOMUtilitiesPrivate.h"
+#include "HTMLNames.h"
+#include "WebFrameImpl.h"
+#include "core/dom/Document.h"
+#include "core/dom/DocumentType.h"
+#include "core/dom/Element.h"
+#include "core/editing/markup.h"
+#include "core/html/HTMLAllCollection.h"
+#include "core/html/HTMLElement.h"
+#include "core/html/HTMLFormElement.h"
+#include "core/html/HTMLHtmlElement.h"
+#include "core/html/HTMLMetaElement.h"
+#include "core/loader/DocumentLoader.h"
+#include "core/loader/FrameLoader.h"
+#include "public/platform/WebVector.h"
+#include "wtf/text/TextEncoding.h"
+
+using namespace WebCore;
+
+namespace blink {
+
+// Maximum length of data buffer which is used to temporary save generated
+// html content data. This is a soft limit which might be passed if a very large
+// contegious string is found in the page.
+static const unsigned dataBufferCapacity = 65536;
+
+WebPageSerializerImpl::SerializeDomParam::SerializeDomParam(const KURL& url,
+                                                            const WTF::TextEncoding& textEncoding,
+                                                            Document* document,
+                                                            const String& directoryName)
+    : url(url)
+    , textEncoding(textEncoding)
+    , document(document)
+    , directoryName(directoryName)
+    , isHTMLDocument(document->isHTMLDocument())
+    , haveSeenDocType(false)
+    , haveAddedCharsetDeclaration(false)
+    , skipMetaElement(0)
+    , isInScriptOrStyleTag(false)
+    , haveAddedXMLProcessingDirective(false)
+    , haveAddedContentsBeforeEnd(false)
+{
+}
+
+String WebPageSerializerImpl::preActionBeforeSerializeOpenTag(
+    const Element* element, SerializeDomParam* param, bool* needSkip)
+{
+    StringBuilder result;
+
+    *needSkip = false;
+    if (param->isHTMLDocument) {
+        // Skip the open tag of original META tag which declare charset since we
+        // have overrided the META which have correct charset declaration after
+        // serializing open tag of HEAD element.
+        if (element->hasTagName(HTMLNames::metaTag)) {
+            const HTMLMetaElement* meta = toHTMLMetaElement(element);
+            // Check whether the META tag has declared charset or not.
+            String equiv = meta->httpEquiv();
+            if (equalIgnoringCase(equiv, "content-type")) {
+                String content = meta->content();
+                if (content.length() && content.contains("charset", false)) {
+                    // Find META tag declared charset, we need to skip it when
+                    // serializing DOM.
+                    param->skipMetaElement = element;
+                    *needSkip = true;
+                }
+            }
+        } else if (isHTMLHtmlElement(element)) {
+            // Check something before processing the open tag of HEAD element.
+            // First we add doc type declaration if original document has it.
+            if (!param->haveSeenDocType) {
+                param->haveSeenDocType = true;
+                result.append(createMarkup(param->document->doctype()));
+            }
+
+            // Add MOTW declaration before html tag.
+            // See http://msdn2.microsoft.com/en-us/library/ms537628(VS.85).aspx.
+            result.append(WebPageSerializer::generateMarkOfTheWebDeclaration(param->url));
+        } else if (element->hasTagName(HTMLNames::baseTag)) {
+            // Comment the BASE tag when serializing dom.
+            result.append("<!--");
+        }
+    } else {
+        // Write XML declaration.
+        if (!param->haveAddedXMLProcessingDirective) {
+            param->haveAddedXMLProcessingDirective = true;
+            // Get encoding info.
+            String xmlEncoding = param->document->xmlEncoding();
+            if (xmlEncoding.isEmpty())
+                xmlEncoding = param->document->encodingName();
+            if (xmlEncoding.isEmpty())
+                xmlEncoding = UTF8Encoding().name();
+            result.append("<?xml version=\"");
+            result.append(param->document->xmlVersion());
+            result.append("\" encoding=\"");
+            result.append(xmlEncoding);
+            if (param->document->xmlStandalone())
+                result.append("\" standalone=\"yes");
+            result.append("\"?>\n");
+        }
+        // Add doc type declaration if original document has it.
+        if (!param->haveSeenDocType) {
+            param->haveSeenDocType = true;
+            result.append(createMarkup(param->document->doctype()));
+        }
+    }
+    return result.toString();
+}
+
+String WebPageSerializerImpl::postActionAfterSerializeOpenTag(
+    const Element* element, SerializeDomParam* param)
+{
+    StringBuilder result;
+
+    param->haveAddedContentsBeforeEnd = false;
+    if (!param->isHTMLDocument)
+        return result.toString();
+    // Check after processing the open tag of HEAD element
+    if (!param->haveAddedCharsetDeclaration
+        && element->hasTagName(HTMLNames::headTag)) {
+        param->haveAddedCharsetDeclaration = true;
+        // Check meta element. WebKit only pre-parse the first 512 bytes
+        // of the document. If the whole <HEAD> is larger and meta is the
+        // end of head part, then this kind of pages aren't decoded correctly
+        // because of this issue. So when we serialize the DOM, we need to
+        // make sure the meta will in first child of head tag.
+        // See http://bugs.webkit.org/show_bug.cgi?id=16621.
+        // First we generate new content for writing correct META element.
+        result.append(WebPageSerializer::generateMetaCharsetDeclaration(
+            String(param->textEncoding.name())));
+
+        param->haveAddedContentsBeforeEnd = true;
+        // Will search each META which has charset declaration, and skip them all
+        // in PreActionBeforeSerializeOpenTag.
+    } else if (element->hasTagName(HTMLNames::scriptTag)
+               || element->hasTagName(HTMLNames::styleTag)) {
+        param->isInScriptOrStyleTag = true;
+    }
+
+    return result.toString();
+}
+
+String WebPageSerializerImpl::preActionBeforeSerializeEndTag(
+    const Element* element, SerializeDomParam* param, bool* needSkip)
+{
+    String result;
+
+    *needSkip = false;
+    if (!param->isHTMLDocument)
+        return result;
+    // Skip the end tag of original META tag which declare charset.
+    // Need not to check whether it's META tag since we guarantee
+    // skipMetaElement is definitely META tag if it's not 0.
+    if (param->skipMetaElement == element)
+        *needSkip = true;
+    else if (element->hasTagName(HTMLNames::scriptTag)
+             || element->hasTagName(HTMLNames::styleTag)) {
+        ASSERT(param->isInScriptOrStyleTag);
+        param->isInScriptOrStyleTag = false;
+    }
+
+    return result;
+}
+
+// After we finish serializing end tag of a element, we give the target
+// element a chance to do some post work to add some additional data.
+String WebPageSerializerImpl::postActionAfterSerializeEndTag(
+    const Element* element, SerializeDomParam* param)
+{
+    StringBuilder result;
+
+    if (!param->isHTMLDocument)
+        return result.toString();
+    // Comment the BASE tag when serializing DOM.
+    if (element->hasTagName(HTMLNames::baseTag)) {
+        result.append("-->");
+        // Append a new base tag declaration.
+        result.append(WebPageSerializer::generateBaseTagDeclaration(
+            param->document->baseTarget()));
+    }
+
+    return result.toString();
+}
+
+void WebPageSerializerImpl::saveHTMLContentToBuffer(
+    const String& result, SerializeDomParam* param)
+{
+    m_dataBuffer.append(result);
+    encodeAndFlushBuffer(WebPageSerializerClient::CurrentFrameIsNotFinished,
+                         param,
+                         DoNotForceFlush);
+}
+
+void WebPageSerializerImpl::encodeAndFlushBuffer(
+    WebPageSerializerClient::PageSerializationStatus status,
+    SerializeDomParam* param,
+    FlushOption flushOption)
+{
+    // Data buffer is not full nor do we want to force flush.
+    if (flushOption != ForceFlush && m_dataBuffer.length() <= dataBufferCapacity)
+        return;
+
+    String content = m_dataBuffer.toString();
+    m_dataBuffer.clear();
+
+    CString encodedContent = param->textEncoding.normalizeAndEncode(content, WTF::EntitiesForUnencodables);
+
+    // Send result to the client.
+    m_client->didSerializeDataForFrame(param->url,
+                                       WebCString(encodedContent.data(), encodedContent.length()),
+                                       status);
+}
+
+void WebPageSerializerImpl::openTagToString(Element* element,
+                                            SerializeDomParam* param)
+{
+    bool needSkip;
+    StringBuilder result;
+    // Do pre action for open tag.
+    result.append(preActionBeforeSerializeOpenTag(element, param, &needSkip));
+    if (needSkip)
+        return;
+    // Add open tag
+    result.append('<');
+    result.append(element->nodeName().lower());
+    // Go through all attributes and serialize them.
+    if (element->hasAttributes()) {
+        unsigned numAttrs = element->attributeCount();
+        for (unsigned i = 0; i < numAttrs; i++) {
+            result.append(' ');
+            // Add attribute pair
+            const Attribute *attribute = element->attributeItem(i);
+            result.append(attribute->name().toString());
+            result.appendLiteral("=\"");
+            if (!attribute->value().isEmpty()) {
+                const String& attrValue = attribute->value();
+
+                // Check whether we need to replace some resource links
+                // with local resource paths.
+                const QualifiedName& attrName = attribute->name();
+                if (elementHasLegalLinkAttribute(element, attrName)) {
+                    // For links start with "javascript:", we do not change it.
+                    if (attrValue.startsWith("javascript:", false))
+                        result.append(attrValue);
+                    else {
+                        // Get the absolute link
+                        WebFrameImpl* subFrame = WebFrameImpl::fromFrameOwnerElement(element);
+                        String completeURL = subFrame ? subFrame->frame()->document()->url() :
+                                                        param->document->completeURL(attrValue);
+                        // Check whether we have local files for those link.
+                        if (m_localLinks.contains(completeURL)) {
+                            if (!param->directoryName.isEmpty()) {
+                                result.appendLiteral("./");
+                                result.append(param->directoryName);
+                                result.append('/');
+                            }
+                            result.append(m_localLinks.get(completeURL));
+                        } else
+                            result.append(completeURL);
+                    }
+                } else {
+                    if (param->isHTMLDocument)
+                        result.append(m_htmlEntities.convertEntitiesInString(attrValue));
+                    else
+                        result.append(m_xmlEntities.convertEntitiesInString(attrValue));
+                }
+            }
+            result.append('\"');
+        }
+    }
+
+    // Do post action for open tag.
+    String addedContents = postActionAfterSerializeOpenTag(element, param);
+    // Complete the open tag for element when it has child/children.
+    if (element->hasChildNodes() || param->haveAddedContentsBeforeEnd)
+        result.append('>');
+    // Append the added contents generate in  post action of open tag.
+    result.append(addedContents);
+    // Save the result to data buffer.
+    saveHTMLContentToBuffer(result.toString(), param);
+}
+
+// Serialize end tag of an specified element.
+void WebPageSerializerImpl::endTagToString(Element* element,
+                                           SerializeDomParam* param)
+{
+    bool needSkip;
+    StringBuilder result;
+    // Do pre action for end tag.
+    result.append(preActionBeforeSerializeEndTag(element, param, &needSkip));
+    if (needSkip)
+        return;
+    // Write end tag when element has child/children.
+    if (element->hasChildNodes() || param->haveAddedContentsBeforeEnd) {
+        result.appendLiteral("</");
+        result.append(element->nodeName().lower());
+        result.append('>');
+    } else {
+        // Check whether we have to write end tag for empty element.
+        if (param->isHTMLDocument) {
+            result.append('>');
+            // FIXME: This code is horribly wrong.  WebPageSerializerImpl must die.
+            if (!element->isHTMLElement() || !toHTMLElement(element)->ieForbidsInsertHTML()) {
+                // We need to write end tag when it is required.
+                result.appendLiteral("</");
+                result.append(element->nodeName().lower());
+                result.append('>');
+            }
+        } else {
+            // For xml base document.
+            result.appendLiteral(" />");
+        }
+    }
+    // Do post action for end tag.
+    result.append(postActionAfterSerializeEndTag(element, param));
+    // Save the result to data buffer.
+    saveHTMLContentToBuffer(result.toString(), param);
+}
+
+void WebPageSerializerImpl::buildContentForNode(Node* node,
+                                                SerializeDomParam* param)
+{
+    switch (node->nodeType()) {
+    case Node::ELEMENT_NODE:
+        // Process open tag of element.
+        openTagToString(toElement(node), param);
+        // Walk through the children nodes and process it.
+        for (Node *child = node->firstChild(); child; child = child->nextSibling())
+            buildContentForNode(child, param);
+        // Process end tag of element.
+        endTagToString(toElement(node), param);
+        break;
+    case Node::TEXT_NODE:
+        saveHTMLContentToBuffer(createMarkup(node), param);
+        break;
+    case Node::ATTRIBUTE_NODE:
+    case Node::DOCUMENT_NODE:
+    case Node::DOCUMENT_FRAGMENT_NODE:
+        // Should not exist.
+        ASSERT_NOT_REACHED();
+        break;
+    // Document type node can be in DOM?
+    case Node::DOCUMENT_TYPE_NODE:
+        param->haveSeenDocType = true;
+    default:
+        // For other type node, call default action.
+        saveHTMLContentToBuffer(createMarkup(node), param);
+        break;
+    }
+}
+
+WebPageSerializerImpl::WebPageSerializerImpl(WebFrame* frame,
+                                             bool recursiveSerialization,
+                                             WebPageSerializerClient* client,
+                                             const WebVector<WebURL>& links,
+                                             const WebVector<WebString>& localPaths,
+                                             const WebString& localDirectoryName)
+    : m_client(client)
+    , m_recursiveSerialization(recursiveSerialization)
+    , m_framesCollected(false)
+    , m_localDirectoryName(localDirectoryName)
+    , m_htmlEntities(false)
+    , m_xmlEntities(true)
+{
+    // Must specify available webframe.
+    ASSERT(frame);
+    m_specifiedWebFrameImpl = toWebFrameImpl(frame);
+    // Make sure we have non 0 client.
+    ASSERT(client);
+    // Build local resources map.
+    ASSERT(links.size() == localPaths.size());
+    for (size_t i = 0; i < links.size(); i++) {
+        KURL url = links[i];
+        ASSERT(!m_localLinks.contains(url.string()));
+        m_localLinks.set(url.string(), localPaths[i]);
+    }
+
+    ASSERT(m_dataBuffer.isEmpty());
+}
+
+void WebPageSerializerImpl::collectTargetFrames()
+{
+    ASSERT(!m_framesCollected);
+    m_framesCollected = true;
+
+    // First, process main frame.
+    m_frames.append(m_specifiedWebFrameImpl);
+    // Return now if user only needs to serialize specified frame, not including
+    // all sub-frames.
+    if (!m_recursiveSerialization)
+        return;
+    // Collect all frames inside the specified frame.
+    for (int i = 0; i < static_cast<int>(m_frames.size()); ++i) {
+        WebFrameImpl* currentFrame = m_frames[i];
+        // Get current using document.
+        Document* currentDoc = currentFrame->frame()->document();
+        // Go through sub-frames.
+        RefPtr<HTMLCollection> all = currentDoc->all();
+
+        for (unsigned i = 0; Node* node = all->item(i); i++) {
+            if (!node->isHTMLElement())
+                continue;
+            Element* element = toElement(node);
+            WebFrameImpl* webFrame =
+                WebFrameImpl::fromFrameOwnerElement(element);
+            if (webFrame)
+                m_frames.append(webFrame);
+        }
+    }
+}
+
+bool WebPageSerializerImpl::serialize()
+{
+    if (!m_framesCollected)
+        collectTargetFrames();
+
+    bool didSerialization = false;
+    KURL mainURL = m_specifiedWebFrameImpl->frame()->document()->url();
+
+    for (unsigned i = 0; i < m_frames.size(); ++i) {
+        WebFrameImpl* webFrame = m_frames[i];
+        Document* document = webFrame->frame()->document();
+        const KURL& url = document->url();
+
+        if (!url.isValid() || !m_localLinks.contains(url.string()))
+            continue;
+
+        didSerialization = true;
+
+        const WTF::TextEncoding& textEncoding = document->encoding().isValid() ? document->encoding() : UTF8Encoding();
+        String directoryName = url == mainURL ? m_localDirectoryName : "";
+
+        SerializeDomParam param(url, textEncoding, document, directoryName);
+
+        Element* documentElement = document->documentElement();
+        if (documentElement)
+            buildContentForNode(documentElement, &param);
+
+        encodeAndFlushBuffer(WebPageSerializerClient::CurrentFrameIsFinished, &param, ForceFlush);
+    }
+
+    ASSERT(m_dataBuffer.isEmpty());
+    m_client->didSerializeDataForFrame(KURL(), WebCString("", 0), WebPageSerializerClient::AllFramesAreFinished);
+    return didSerialization;
+}
+
+}  // namespace blink
```


### `third_party/WebKit/Source/web/WebPageSerializerImpl.h`

```diff
@@ -0,0 +1,192 @@
+/*
+ * Copyright (C) 2009 Google Inc. All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are
+ * met:
+ *
+ *     * Redistributions of source code must retain the above copyright
+ * notice, this list of conditions and the following disclaimer.
+ *     * Redistributions in binary form must reproduce the above
+ * copyright notice, this list of conditions and the following disclaimer
+ * in the documentation and/or other materials provided with the
+ * distribution.
+ *     * Neither the name of Google Inc. nor the names of its
+ * contributors may be used to endorse or promote products derived from
+ * this software without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+ * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+ * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+ * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+ * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+ * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+ * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+ * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+ * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifndef WebPageSerializerImpl_h
+#define WebPageSerializerImpl_h
+
+#include "wtf/Forward.h"
+#include "wtf/HashMap.h"
+#include "wtf/Vector.h"
+#include "wtf/text/StringBuilder.h"
+#include "wtf/text/StringHash.h"
+#include "wtf/text/WTFString.h"
+
+#include "WebEntities.h"
+#include "WebPageSerializer.h"
+#include "WebPageSerializerClient.h"
+#include "public/platform/WebString.h"
+#include "public/platform/WebURL.h"
+
+namespace WTF{
+class TextEncoding;
+}
+
+namespace WebCore {
+class Document;
+class Element;
+class Node;
+}
+
+namespace blink {
+class WebFrameImpl;
+
+// Get html data by serializing all frames of current page with lists
+// which contain all resource links that have local copy.
+// contain all saved auxiliary files included all sub frames and resources.
+// This function will find out all frames and serialize them to HTML data.
+// We have a data buffer to temporary saving generated html data. We will
+// sequentially call WebViewDelegate::SendSerializedHtmlData once the data
+// buffer is full. See comments of WebViewDelegate::SendSerializedHtmlData
+// for getting more information.
+class WebPageSerializerImpl {
+public:
+    // Do serialization action. Return false means no available frame has been
+    // serialized, otherwise return true.
+    bool serialize();
+
+    // The parameter specifies which frame need to be serialized.
+    // The parameter recursive_serialization specifies whether we need to
+    // serialize all sub frames of the specified frame or not.
+    // The parameter delegate specifies the pointer of interface
+    // DomSerializerDelegate provide sink interface which can receive the
+    // individual chunks of data to be saved.
+    // The parameter links contain original URLs of all saved links.
+    // The parameter local_paths contain corresponding local file paths of all
+    // saved links, which matched with vector:links one by one.
+    // The parameter local_directory_name is relative path of directory which
+    // contain all saved auxiliary files included all sub frames and resources.
+    WebPageSerializerImpl(WebFrame* frame,
+                          bool recursive,
+                          WebPageSerializerClient* client,
+                          const WebVector<WebURL>& links,
+                          const WebVector<WebString>& localPaths,
+                          const WebString& localDirectoryName);
+
+private:
+    // Specified frame which need to be serialized;
+    WebFrameImpl* m_specifiedWebFrameImpl;
+    // Pointer of WebPageSerializerClient
+    WebPageSerializerClient* m_client;
+    // This hash map is used to map resource URL of original link to its local
+    // file path.
+    typedef HashMap<WTF::String, WTF::String> LinkLocalPathMap;
+    // local_links_ include all pair of local resource path and corresponding
+    // original link.
+    LinkLocalPathMap m_localLinks;
+    // Data buffer for saving result of serialized DOM data.
+    StringBuilder m_dataBuffer;
+    // Passing true to recursive_serialization_ indicates we will serialize not
+    // only the specified frame but also all sub-frames in the specific frame.
+    // Otherwise we only serialize the specified frame excluded all sub-frames.
+    bool m_recursiveSerialization;
+    // Flag indicates whether we have collected all frames which need to be
+    // serialized or not;
+    bool m_framesCollected;
+    // Local directory name of all local resource files.
+    WTF::String m_localDirectoryName;
+    // Vector for saving all frames which need to be serialized.
+    Vector<WebFrameImpl*> m_frames;
+
+    // Web entities conversion maps.
+    WebEntities m_htmlEntities;
+    WebEntities m_xmlEntities;
+
+    struct SerializeDomParam {
+        const WebCore::KURL& url;
+        const WTF::TextEncoding& textEncoding;
+        WebCore::Document* document;
+        const WTF::String& directoryName;
+        bool isHTMLDocument; // document.isHTMLDocument()
+        bool haveSeenDocType;
+        bool haveAddedCharsetDeclaration;
+        // This meta element need to be skipped when serializing DOM.
+        const WebCore::Element* skipMetaElement;
+        // Flag indicates we are in script or style tag.
+        bool isInScriptOrStyleTag;
+        bool haveAddedXMLProcessingDirective;
+        // Flag indicates whether we have added additional contents before end tag.
+        // This flag will be re-assigned in each call of function
+        // PostActionAfterSerializeOpenTag and it could be changed in function
+        // PreActionBeforeSerializeEndTag if the function adds new contents into
+        // serialization stream.
+        bool haveAddedContentsBeforeEnd;
+
+        SerializeDomParam(const WebCore::KURL&, const WTF::TextEncoding&, WebCore::Document*, const WTF::String& directoryName);
+    };
+
+    // Collect all target frames which need to be serialized.
+    void collectTargetFrames();
+    // Before we begin serializing open tag of a element, we give the target
+    // element a chance to do some work prior to add some additional data.
+    WTF::String preActionBeforeSerializeOpenTag(const WebCore::Element* element,
+                                                    SerializeDomParam* param,
+                                                    bool* needSkip);
+    // After we finish serializing open tag of a element, we give the target
+    // element a chance to do some post work to add some additional data.
+    WTF::String postActionAfterSerializeOpenTag(const WebCore::Element* element,
+                                                    SerializeDomParam* param);
+    // Before we begin serializing end tag of a element, we give the target
+    // element a chance to do some work prior to add some additional data.
+    WTF::String preActionBeforeSerializeEndTag(const WebCore::Element* element,
+                                                   SerializeDomParam* param,
+                                                   bool* needSkip);
+    // After we finish serializing end tag of a element, we give the target
+    // element a chance to do some post work to add some additional data.
+    WTF::String postActionAfterSerializeEndTag(const WebCore::Element* element,
+                                                   SerializeDomParam* param);
+    // Save generated html content to data buffer.
+    void saveHTMLContentToBuffer(const WTF::String& content,
+                                 SerializeDomParam* param);
+
+    enum FlushOption {
+        ForceFlush,
+        DoNotForceFlush,
+    };
+
+    // Flushes the content buffer by encoding and sending the content to the
+    // WebPageSerializerClient. Content is not flushed if the buffer is not full
+    // unless force is 1.
+    void encodeAndFlushBuffer(WebPageSerializerClient::PageSerializationStatus status,
+                              SerializeDomParam* param,
+                              FlushOption);
+    // Serialize open tag of an specified element.
+    void openTagToString(WebCore::Element*,
+                         SerializeDomParam* param);
+    // Serialize end tag of an specified element.
+    void endTagToString(WebCore::Element*,
+                        SerializeDomParam* param);
+    // Build content for a specified node
+    void buildContentForNode(WebCore::Node*,
+                             SerializeDomParam* param);
+};
+
+} // namespace blink
+
+#endif
```


### `third_party/WebKit/Source/web/tests/MHTMLTest.cpp`

```diff
@@ -1,169 +0,0 @@
-/*
- * Copyright (C) 2011 Google Inc. All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions are
- * met:
- *
- *     * Redistributions of source code must retain the above copyright
- * notice, this list of conditions and the following disclaimer.
- *     * Redistributions in binary form must reproduce the above
- * copyright notice, this list of conditions and the following disclaimer
- * in the documentation and/or other materials provided with the
- * distribution.
- *     * Neither the name of Google Inc. nor the names of its
- * contributors may be used to endorse or promote products derived from
- * this software without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
- * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
- * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
- * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
- * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
- * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
- * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
- * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
- * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
- */
-#include "config.h"
-
-#include "URLTestHelpers.h"
-#include "platform/SerializedResource.h"
-#include "platform/SharedBuffer.h"
-#include "platform/mhtml/MHTMLArchive.h"
-#include "public/platform/Platform.h"
-#include "public/platform/WebUnitTestSupport.h"
-#include <gtest/gtest.h>
-
-using namespace WebCore;
-using namespace blink;
-
-using blink::URLTestHelpers::toKURL;
-
-namespace {
-
-class LineReader {
-public:
-    LineReader(const std::string& text) : m_text(text), m_index(0) { }
-    bool getNextLine(std::string* line)
-    {
-        line->clear();
-        if (m_index >= m_text.length())
-            return false;
-
-        size_t endOfLineIndex = m_text.find("\r\n", m_index);
-        if (endOfLineIndex == std::string::npos) {
-            *line = m_text.substr(m_index);
-            m_index = m_text.length();
-        } else {
-            *line = m_text.substr(m_index, endOfLineIndex - m_index);
-            m_index = endOfLineIndex + 2;
-        }
-        return true;
-    }
-
-private:
-    std::string m_text;
-    size_t m_index;
-};
-
-
-class MHTMLTest : public testing::Test {
-public:
-    MHTMLTest()
-    {
-        m_filePath = Platform::current()->unitTestSupport()->webKitRootDir();
-        m_filePath.append("/Source/web/tests/data/mhtml/");
-    }
-
-protected:
-    virtual void SetUp()
-    {
-    }
-
-    virtual void TearDown()
-    {
-    }
-
-    void addResource(const char* url, const char* mime, PassRefPtr<SharedBuffer> data)
-    {
-        SerializedResource resource(toKURL(url), mime, data);
-        m_resources.append(resource);
-    }
-
-    void addResource(const char* url, const char* mime, const char* fileName)
-    {
-        addResource(url, mime, readFile(fileName));
-    }
-
-    void addTestResources()
-    {
-        addResource("http://www.test.com", "text/html", "css_test_page.html");
-        addResource("http://www.test.com/link_styles.css", "text/css", "link_styles.css");
-        addResource("http://www.test.com/import_style_from_link.css", "text/css", "import_style_from_link.css");
-        addResource("http://www.test.com/import_styles.css", "text/css", "import_styles.css");
-        addResource("http://www.test.com/red_background.png", "image/png", "red_background.png");
-        addResource("http://www.test.com/orange_background.png", "image/png", "orange_background.png");
-        addResource("http://www.test.com/yellow_background.png", "image/png", "yellow_background.png");
-        addResource("http://www.test.com/green_background.png", "image/png", "green_background.png");
-        addResource("http://www.test.com/blue_background.png", "image/png", "blue_background.png");
-        addResource("http://www.test.com/purple_background.png", "image/png", "purple_background.png");
-        addResource("http://www.test.com/ul-dot.png", "image/png", "ul-dot.png");
-        addResource("http://www.test.com/ol-dot.png", "image/png", "ol-dot.png");
-    }
-
-    PassRefPtr<SharedBuffer> serialize(const char *title, const char *mime,  MHTMLArchive::EncodingPolicy encodingPolicy)
-    {
-        return MHTMLArchive::generateMHTMLData(m_resources, encodingPolicy, title, mime);
-    }
-
-
-private:
-
-    PassRefPtr<SharedBuffer> readFile(const char* fileName)
-    {
-        String filePath = m_filePath + fileName;
-        return Platform::current()->unitTestSupport()->readFromFile(filePath);
-    }
-
-    String m_filePath;
-    Vector<SerializedResource> m_resources;
-};
-
-TEST_F(MHTMLTest, FAILS_TestMHTMLEncoding)
-{
-    addTestResources();
-    RefPtr<SharedBuffer> data  = serialize("Test Serialization", "text/html", MHTMLArchive::UseDefaultEncoding);
-
-    // Read the MHTML data line per line and do some pseudo-parsing to make sure the right encoding is used for the different sections.
-    LineReader lineReader(std::string(data->data()));
-    int sectionCheckedCount = 0;
-    const char* expectedEncoding = 0;
-    std::string line;
-    while (lineReader.getNextLine(&line)) {
-        if (!line.find("Content-Type:")) {
-            ASSERT_FALSE(expectedEncoding);
-            if (line.find("multipart/related;") != std::string::npos) {
-                // Skip this one, it's part of the MHTML header.
-                continue;
-            }
-            if (line.find("text/") != std::string::npos)
-                expectedEncoding = "quoted-printable";
-            else if (line.find("image/") != std::string::npos)
-                expectedEncoding = "base64";
-            else
-                FAIL() << "Unexpected Content-Type: " << line;
-            continue;
-        }
-        if (!line.find("Content-Transfer-Encoding:")) {
-            ASSERT_TRUE(expectedEncoding);
-            EXPECT_TRUE(line.find(expectedEncoding) != std::string::npos);
-            expectedEncoding = 0;
-            sectionCheckedCount++;
-        }
-    }
-    EXPECT_EQ(12, sectionCheckedCount);
-}
-}
```


### `third_party/WebKit/Source/web/tests/PageSerializerTest.cpp`

```diff
@@ -105,19 +105,9 @@ class PageSerializerTest : public testing::Test {
         m_folder = WebString::fromUTF8(folder);
     }
 
-    void setRewriteURLFolder(const char* folder)
-    {
-        m_rewriteFolder = folder;
-    }
-
-    void registerURL(const char* url, const char* file, const char* mimeType)
-    {
-        registerMockedURLLoad(KURL(m_baseUrl, url), WebString::fromUTF8(file), m_folder, WebString::fromUTF8(mimeType));
-    }
-
     void registerURL(const char* file, const char* mimeType)
     {
-        registerURL(file, file, mimeType);
+        registerMockedURLLoad(KURL(m_baseUrl, file), WebString::fromUTF8(file), m_folder, WebString::fromUTF8(mimeType));
     }
 
     void registerErrorURL(const char* file, int statusCode)
@@ -134,11 +124,6 @@ class PageSerializerTest : public testing::Test {
         Platform::current()->unitTestSupport()->registerMockedErrorURL(KURL(m_baseUrl, file), response, error);
     }
 
-    void registerRewriteURL(const char* fromURL, const char* toURL)
-    {
-        m_rewriteURLs.add(fromURL, toURL);
-    }
-
     void serialize(const char* url)
     {
         WebURLRequest urlRequest;
@@ -152,8 +137,7 @@ class PageSerializerTest : public testing::Test {
         // Server the delayed resources.
         Platform::current()->unitTestSupport()->serveAsynchronousMockedRequests();
 
-        PageSerializer serializer(&m_resources,
-            m_rewriteURLs.isEmpty() ? 0: &m_rewriteURLs, m_rewriteFolder);
+        PageSerializer serializer(&m_resources);
         serializer.serialize(m_webViewImpl->mainFrameImpl()->frame()->page());
     }
 
@@ -189,16 +173,6 @@ class PageSerializerTest : public testing::Test {
         return String();
     }
 
-    // For debugging
-    void printResources()
-    {
-        printf("Printing resources (%zu resources in total)\n", m_resources.size());
-        for (size_t i = 0; i < m_resources.size(); ++i) {
-            printf("%zu. '%s', '%s'\n", i, m_resources[i].url.string().utf8().data(),
-                m_resources[i].mimeType.utf8().data());
-        }
-    }
-
     WebViewImpl* m_webViewImpl;
 
 private:
@@ -207,170 +181,26 @@ class PageSerializerTest : public testing::Test {
     WebString m_folder;
     KURL m_baseUrl;
     Vector<SerializedResource> m_resources;
-    LinkLocalPathMap m_rewriteURLs;
-    String m_rewriteFolder;
 };
 
-TEST_F(PageSerializerTest, HTMLElements)
-{
-    setBaseFolder("pageserializer/elements/");
-
-    registerURL("elements.html", "text/html");
-    registerURL("style.css", "style.css", "text/css");
-    registerURL("copyright.html", "text.txt", "text/html");
-    registerURL("script.js", "text.txt", "text/javascript");
-
-    registerURL("bodyBackground.png", "image.png", "image/png");
-
-    registerURL("imageSrc.png", "image.png", "image/png");
-
-    registerURL("inputImage.png", "image.png", "image/png");
-
-    registerURL("tableBackground.png", "image.png", "image/png");
-    registerURL("trBackground.png", "image.png", "image/png");
-    registerURL("tdBackground.png", "image.png", "image/png");
-
-    registerURL("blockquoteCite.html", "text.txt", "text/html");
-    registerURL("qCite.html", "text.txt", "text/html");
-    registerURL("delCite.html", "text.txt", "text/html");
-    registerURL("insCite.html", "text.txt", "text/html");
-
-    registerErrorURL("nonExisting.png", 404);
-
-    serialize("elements.html");
-
-    EXPECT_EQ(8U, getResources().size());
-
-    EXPECT_TRUE(isSerialized("elements.html", "text/html"));
-    EXPECT_TRUE(isSerialized("style.css", "text/css"));
-    EXPECT_TRUE(isSerialized("bodyBackground.png", "image/png"));
-    EXPECT_TRUE(isSerialized("imageSrc.png", "image/png"));
-    EXPECT_TRUE(isSerialized("inputImage.png", "image/png"));
-    EXPECT_TRUE(isSerialized("tableBackground.png", "image/png"));
-    EXPECT_TRUE(isSerialized("trBackground.png", "image/png"));
-    EXPECT_TRUE(isSerialized("tdBackground.png", "image/png"));
-    EXPECT_FALSE(isSerialized("nonExisting.png", "image/png"));
-}
-
-TEST_F(PageSerializerTest, Frames)
-{
-    setBaseFolder("pageserializer/frames/");
-
-    registerURL("simple_frames.html", "text/html");
-    registerURL("simple_frames_top.html", "text/html");
-    registerURL("simple_frames_1.html", "text/html");
-    registerURL("simple_frames_3.html", "text/html");
-
-    registerURL("frame_1.png", "image.png", "image/png");
-    registerURL("frame_2.png", "image.png", "image/png");
-    registerURL("frame_3.png", "image.png", "image/png");
-    registerURL("frame_4.png", "image.png", "image/png");
-
-    serialize("simple_frames.html");
-
-    EXPECT_EQ(8U, getResources().size());
-
-    EXPECT_TRUE(isSerialized("simple_frames.html", "text/html"));
-    EXPECT_TRUE(isSerialized("simple_frames_top.html", "text/html"));
-    EXPECT_TRUE(isSerialized("simple_frames_1.html", "text/html"));
-    EXPECT_TRUE(isSerialized("simple_frames_3.html", "text/html"));
-
-    EXPECT_TRUE(isSerialized("frame_1.png", "image/png"));
-    EXPECT_TRUE(isSerialized("frame_2.png", "image/png"));
-    EXPECT_TRUE(isSerialized("frame_3.png", "image/png"));
-    EXPECT_TRUE(isSerialized("frame_4.png", "image/png"));
-}
-
-TEST_F(PageSerializerTest, IFrames)
-{
-    setBaseFolder("pageserializer/frames/");
-
-    registerURL("top_frame.html", "text/html");
-    registerURL("simple_iframe.html", "text/html");
-    registerURL("object_iframe.html", "text/html");
-    registerURL("embed_iframe.html", "text/html");
-
-    registerURL("top.png", "image.png", "image/png");
-    registerURL("simple.png", "image.png", "image/png");
-    registerURL("object.png", "image.png", "image/png");
-    registerURL("embed.png", "image.png", "image/png");
-
-    serialize("top_frame.html");
-
-    EXPECT_EQ(8U, getResources().size());
 
-    EXPECT_TRUE(isSerialized("top_frame.html", "text/html"));
-    EXPECT_TRUE(isSerialized("simple_iframe.html", "text/html"));
-    EXPECT_TRUE(isSerialized("object_iframe.html", "text/html"));
-    EXPECT_TRUE(isSerialized("embed_iframe.html", "text/html"));
-
-    EXPECT_TRUE(isSerialized("top.png", "image/png"));
-    EXPECT_TRUE(isSerialized("simple.png", "image/png"));
-    EXPECT_TRUE(isSerialized("object.png", "image/png"));
-    EXPECT_TRUE(isSerialized("embed.png", "image/png"));
-}
-
-// Tests that when serializing a page with blank frames these are reported with their resources.
-TEST_F(PageSerializerTest, BlankFrames)
+TEST_F(PageSerializerTest, InputImage)
 {
-    setBaseFolder("pageserializer/frames/");
+    setBaseFolder("pageserializer/input-image/");
 
-    registerURL("blank_frames.html", "text/html");
-    registerURL("red_background.png", "image.png", "image/png");
-    registerURL("orange_background.png", "image.png", "image/png");
-    registerURL("blue_background.png", "image.png", "image/png");
+    registerURL("input-image.html", "text/html");
+    registerURL("button.png", "image/png");
+    registerErrorURL("non-existing-button.png", 404);
 
-    serialize("blank_frames.html");
+    serialize("input-image.html");
 
-    EXPECT_EQ(7U, getResources().size());
-
-    EXPECT_TRUE(isSerialized("http://www.test.com/red_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("http://www.test.com/orange_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("http://www.test.com/blue_background.png", "image/png"));
-    // The blank frames should have got a magic URL.
-    EXPECT_TRUE(isSerialized("wyciwyg://frame/0", "text/html"));
-    EXPECT_TRUE(isSerialized("wyciwyg://frame/1", "text/html"));
-    EXPECT_TRUE(isSerialized("wyciwyg://frame/2", "text/html"));
-}
-
-TEST_F(PageSerializerTest, CSS)
-{
-    setBaseFolder("pageserializer/css/");
-
-    registerURL("css_test_page.html", "text/html");
-    registerURL("link_styles.css", "text/css");
-    registerURL("import_style_from_link.css", "text/css");
-    registerURL("import_styles.css", "text/css");
-    registerURL("red_background.png", "image.png", "image/png");
-    registerURL("orange_background.png", "image.png", "image/png");
-    registerURL("yellow_background.png", "image.png", "image/png");
-    registerURL("green_background.png", "image.png", "image/png");
-    registerURL("blue_background.png", "image.png", "image/png");
-    registerURL("purple_background.png", "image.png", "image/png");
-    registerURL("ul-dot.png", "image.png", "image/png");
-    registerURL("ol-dot.png", "image.png", "image/png");
-
-    serialize("css_test_page.html");
-
-    EXPECT_EQ(12U, getResources().size());
-
-    EXPECT_TRUE(isSerialized("css_test_page.html", "text/html"));
-    EXPECT_TRUE(isSerialized("link_styles.css", "text/css"));
-    EXPECT_TRUE(isSerialized("import_styles.css", "text/css"));
-    EXPECT_TRUE(isSerialized("import_style_from_link.css", "text/css"));
-    EXPECT_TRUE(isSerialized("red_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("orange_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("yellow_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("green_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("blue_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("purple_background.png", "image/png"));
-    EXPECT_TRUE(isSerialized("ul-dot.png", "image/png"));
-    EXPECT_TRUE(isSerialized("ol-dot.png", "image/png"));
+    EXPECT_TRUE(isSerialized("button.png", "image/png"));
+    EXPECT_FALSE(isSerialized("non-existing-button.png", "image/png"));
 }
 
 TEST_F(PageSerializerTest, XMLDeclaration)
 {
-    setBaseFolder("pageserializer/xml/");
+    setBaseFolder("pageserializer/xmldecl/");
 
     registerURL("xmldecl.xml", "text/xml");
     serialize("xmldecl.xml");
@@ -383,11 +213,11 @@ TEST_F(PageSerializerTest, DTD)
 {
     setBaseFolder("pageserializer/dtd/");
 
-    registerURL("html5.html", "text/html");
-    serialize("html5.html");
+    registerURL("dtd.html", "text/html");
+    serialize("dtd.html");
 
     String expectedStart("<!DOCTYPE html>");
-    EXPECT_TRUE(getSerializedData("html5.html").startsWith(expectedStart));
+    EXPECT_TRUE(getSerializedData("dtd.html").startsWith(expectedStart));
 }
 
 TEST_F(PageSerializerTest, Font)
@@ -402,96 +232,4 @@ TEST_F(PageSerializerTest, Font)
     EXPECT_TRUE(isSerialized("font.ttf", "application/octet-stream"));
 }
 
-TEST_F(PageSerializerTest, DataURI)
-{
-    setBaseFolder("pageserializer/datauri/");
-
-    registerURL("page_with_data.html", "text/html");
-
-    serialize("page_with_data.html");
-
-    EXPECT_EQ(1U, getResources().size());
-    EXPECT_TRUE(isSerialized("page_with_data.html", "text/html"));
-}
-
-TEST_F(PageSerializerTest, DataURIMorphing)
-{
-    setBaseFolder("pageserializer/datauri/");
-
-    registerURL("page_with_morphing_data.html", "text/html");
-
-    serialize("page_with_morphing_data.html");
-
-    EXPECT_EQ(2U, getResources().size());
-    EXPECT_TRUE(isSerialized("page_with_morphing_data.html", "text/html"));
-}
-
-TEST_F(PageSerializerTest, RewriteLinksSimple)
-{
-    setBaseFolder("pageserializer/rewritelinks/");
-    setRewriteURLFolder("folder");
-
-    registerURL("rewritelinks_simple.html", "text/html");
-    registerURL("absolute.png", "image.png", "image/png");
-    registerURL("relative.png", "image.png", "image/png");
-    registerRewriteURL("http://www.test.com/absolute.png", "a.png");
-    registerRewriteURL("http://www.test.com/relative.png", "b.png");
-
-    serialize("rewritelinks_simple.html");
-
-    EXPECT_EQ(3U, getResources().size());
-    EXPECT_NE(getSerializedData("rewritelinks_simple.html", "text/html").find("./folder/a.png"), kNotFound);
-    EXPECT_NE(getSerializedData("rewritelinks_simple.html", "text/html").find("./folder/b.png"), kNotFound);
-}
-
-TEST_F(PageSerializerTest, RewriteLinksBase)
-{
-    setBaseFolder("pageserializer/rewritelinks/");
-    setRewriteURLFolder("folder");
-
-    registerURL("rewritelinks_base.html", "text/html");
-    registerURL("images/here/image.png", "image.png", "image/png");
-    registerURL("images/here/or/in/here/image.png", "image.png", "image/png");
-    registerURL("or/absolute.png", "image.png", "image/png");
-    registerRewriteURL("http://www.test.com/images/here/image.png", "a.png");
-    registerRewriteURL("http://www.test.com/images/here/or/in/here/image.png", "b.png");
-    registerRewriteURL("http://www.test.com/or/absolute.png", "c.png");
-
-    serialize("rewritelinks_base.html");
-
-    EXPECT_EQ(4U, getResources().size());
-    EXPECT_NE(getSerializedData("rewritelinks_base.html", "text/html").find("./folder/a.png"), kNotFound);
-    EXPECT_NE(getSerializedData("rewritelinks_base.html", "text/html").find("./folder/b.png"), kNotFound);
-    EXPECT_NE(getSerializedData("rewritelinks_base.html", "text/html").find("./folder/c.png"), kNotFound);
-}
-
-// Test that we don't regress https://bugs.webkit.org/show_bug.cgi?id=99105
-TEST_F(PageSerializerTest, SVGImageDontCrash)
-{
-    setBaseFolder("pageserializer/svg/");
-
-    registerURL("page_with_svg_image.html", "text/html");
-    registerURL("green_rectangle.svg", "image/svg+xml");
-
-    serialize("page_with_svg_image.html");
-
-    EXPECT_EQ(2U, getResources().size());
-
-    EXPECT_TRUE(isSerialized("green_rectangle.svg", "image/svg+xml"));
-    EXPECT_GT(getSerializedData("green_rectangle.svg", "image/svg+xml").length(), 250U);
-}
-
-TEST_F(PageSerializerTest, NamespaceElementsDontCrash)
-{
-    setBaseFolder("pageserializer/namespace/");
-
-    registerURL("namespace_element.html", "text/html");
-
-    serialize("namespace_element.html");
-
-    EXPECT_EQ(1U, getResources().size());
-    EXPECT_TRUE(isSerialized("namespace_element.html", "text/html"));
-    EXPECT_GT(getSerializedData("namespace_element.html", "text/html").length(), 0U);
-}
-
 }
```


### `third_party/WebKit/Source/web/tests/WebFrameTest.cpp`

```diff
@@ -4031,7 +4031,7 @@ TEST_F(WebFrameTest, HTMLDocument)
 
 TEST_F(WebFrameTest, EmptyDocument)
 {
-    registerMockedHttpURLLoad("pageserializer/svg/green_rectangle.svg");
+    registerMockedHttpURLLoad("pageserializer/green_rectangle.svg");
 
     TestWillInsertBodyWebFrameClient webFrameClient;
     FrameTestHelpers::WebViewHelper webViewHelper;
```


### `third_party/WebKit/Source/web/tests/WebPageNewSerializerTest.cpp`

```diff
@@ -0,0 +1,440 @@
+/*
+ * Copyright (C) 2011 Google Inc. All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are
+ * met:
+ *
+ *     * Redistributions of source code must retain the above copyright
+ * notice, this list of conditions and the following disclaimer.
+ *     * Redistributions in binary form must reproduce the above
+ * copyright notice, this list of conditions and the following disclaimer
+ * in the documentation and/or other materials provided with the
+ * distribution.
+ *     * Neither the name of Google Inc. nor the names of its
+ * contributors may be used to endorse or promote products derived from
+ * this software without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+ * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+ * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+ * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+ * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+ * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+ * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+ * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+ * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+ */
+#include "config.h"
+
+#include "FrameTestHelpers.h"
+#include "URLTestHelpers.h"
+#include "WebFrame.h"
+#include "WebFrameClient.h"
+#include "WebPageSerializer.h"
+#include "WebPageSerializerClient.h"
+#include "WebScriptSource.h"
+#include "WebSettings.h"
+#include "WebView.h"
+#include <gtest/gtest.h>
+#include "public/platform/Platform.h"
+#include "public/platform/WebString.h"
+#include "public/platform/WebThread.h"
+#include "public/platform/WebURL.h"
+#include "public/platform/WebURLRequest.h"
+#include "public/platform/WebURLResponse.h"
+#include "public/platform/WebUnitTestSupport.h"
+
+using namespace blink;
+using blink::FrameTestHelpers::runPendingTasks;
+using blink::URLTestHelpers::toKURL;
+using blink::URLTestHelpers::registerMockedURLLoad;
+
+namespace {
+
+class LineReader {
+public:
+    LineReader(const std::string& text) : m_text(text), m_index(0) { }
+    bool getNextLine(std::string* line)
+    {
+        line->clear();
+        if (m_index >= m_text.length())
+            return false;
+
+        size_t endOfLineIndex = m_text.find("\r\n", m_index);
+        if (endOfLineIndex == std::string::npos) {
+            *line = m_text.substr(m_index);
+            m_index = m_text.length();
+        } else {
+            *line = m_text.substr(m_index, endOfLineIndex - m_index);
+            m_index = endOfLineIndex + 2;
+        }
+        return true;
+    }
+
+private:
+    std::string m_text;
+    size_t m_index;
+};
+
+class TestWebFrameClient : public WebFrameClient {
+public:
+    virtual ~TestWebFrameClient() { }
+};
+
+class LengthCountingWebPageSerializerClient : public WebPageSerializerClient {
+public:
+    LengthCountingWebPageSerializerClient(size_t* counter)
+        : m_counter(counter)
+    {
+    }
+
+    virtual void didSerializeDataForFrame(const WebURL& frameURL, const WebCString& data, PageSerializationStatus status) {
+        *m_counter += data.length();
+    }
+
+private:
+    size_t* m_counter;
+};
+
+class WebPageNewSerializeTest : public testing::Test {
+public:
+    WebPageNewSerializeTest()
+        : m_htmlMimeType(WebString::fromUTF8("text/html"))
+        , m_xhtmlMimeType(WebString::fromUTF8("application/xhtml+xml"))
+        , m_cssMimeType(WebString::fromUTF8("text/css"))
+        , m_pngMimeType(WebString::fromUTF8("image/png"))
+        , m_svgMimeType(WebString::fromUTF8("image/svg+xml"))
+    {
+    }
+
+protected:
+    virtual void SetUp()
+    {
+        // Create and initialize the WebView.
+        m_webView = WebView::create(0);
+        m_mainFrame = WebFrame::create(&m_webFrameClient);
+
+        // We want the images to load and JavaScript to be on.
+        WebSettings* settings = m_webView->settings();
+        settings->setImagesEnabled(true);
+        settings->setLoadsImagesAutomatically(true);
+        settings->setJavaScriptEnabled(true);
+
+        m_webView->setMainFrame(m_mainFrame);
+    }
+
+    virtual void TearDown()
+    {
+        Platform::current()->unitTestSupport()->unregisterAllMockedURLs();
+        m_webView->close();
+        m_mainFrame->close();
+    }
+
+    WebURL setUpCSSTestPage()
+    {
+        WebURL topFrameURL = toKURL("http://www.test.com");
+        registerMockedURLLoad(topFrameURL, WebString::fromUTF8("css_test_page.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/link_styles.css"), WebString::fromUTF8("link_styles.css"), WebString::fromUTF8("pageserializer/"), cssMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/import_style_from_link.css"), WebString::fromUTF8("import_style_from_link.css"), WebString::fromUTF8("pageserializer/"), cssMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/import_styles.css"), WebString::fromUTF8("import_styles.css"), WebString::fromUTF8("pageserializer/"), cssMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/red_background.png"), WebString::fromUTF8("red_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/orange_background.png"), WebString::fromUTF8("orange_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/yellow_background.png"), WebString::fromUTF8("yellow_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/green_background.png"), WebString::fromUTF8("green_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/blue_background.png"), WebString::fromUTF8("blue_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/purple_background.png"), WebString::fromUTF8("purple_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/ul-dot.png"), WebString::fromUTF8("ul-dot.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        registerMockedURLLoad(toKURL("http://www.test.com/ol-dot.png"), WebString::fromUTF8("ol-dot.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+        return topFrameURL;
+    }
+
+    void loadURLInTopFrame(const WebURL& url)
+    {
+        WebURLRequest urlRequest;
+        urlRequest.initialize();
+        urlRequest.setURL(url);
+        m_webView->mainFrame()->loadRequest(urlRequest);
+        // Make sure any pending request get served.
+        Platform::current()->unitTestSupport()->serveAsynchronousMockedRequests();
+        // Some requests get delayed, run the timer.
+        runPendingTasks();
+        // Server the delayed resources.
+        Platform::current()->unitTestSupport()->serveAsynchronousMockedRequests();
+    }
+
+    const WebString& htmlMimeType() const { return m_htmlMimeType; }
+    const WebString& xhtmlMimeType() const { return m_xhtmlMimeType; }
+    const WebString& cssMimeType() const { return m_cssMimeType; }
+    const WebString& pngMimeType() const { return m_pngMimeType; }
+    const WebString& svgMimeType() const { return m_svgMimeType; }
+
+    static bool resourceVectorContains(const WebVector<WebPageSerializer::Resource>& resources, const char* url, const char* mimeType)
+    {
+        WebURL webURL = WebURL(toKURL(url));
+        for (size_t i = 0; i < resources.size(); ++i) {
+            const WebPageSerializer::Resource& resource = resources[i];
+            if (resource.url == webURL && !resource.data.isEmpty() && !resource.mimeType.compare(WebCString(mimeType)))
+                return true;
+        }
+        return false;
+    }
+
+    WebView* m_webView;
+
+private:
+    WebString m_htmlMimeType;
+    WebString m_xhtmlMimeType;
+    WebString m_cssMimeType;
+    WebString m_pngMimeType;
+    WebString m_svgMimeType;
+    TestWebFrameClient m_webFrameClient;
+    WebFrame* m_mainFrame;
+};
+
+// Tests that a page with resources and sub-frame is reported with all its resources.
+TEST_F(WebPageNewSerializeTest, PageWithFrames)
+{
+    // Register the mocked frames.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad(topFrameURL, WebString::fromUTF8("top_frame.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/iframe.html"), WebString::fromUTF8("iframe.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/iframe2.html"), WebString::fromUTF8("iframe2.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/red_background.png"), WebString::fromUTF8("red_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/green_background.png"), WebString::fromUTF8("green_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/blue_background.png"), WebString::fromUTF8("blue_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+
+    loadURLInTopFrame(topFrameURL);
+
+    WebVector<WebPageSerializer::Resource> resources;
+    WebPageSerializer::serialize(m_webView, &resources);
+    ASSERT_FALSE(resources.isEmpty());
+
+    // The first resource should be the main-frame.
+    const WebPageSerializer::Resource& resource = resources[0];
+    EXPECT_TRUE(resource.url == WebURL(toKURL("http://www.test.com")));
+    EXPECT_EQ(0, resource.mimeType.compare(WebCString("text/html")));
+    EXPECT_FALSE(resource.data.isEmpty());
+
+    EXPECT_EQ(6U, resources.size()); // There should be no duplicates.
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/red_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/green_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/blue_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/iframe.html", "text/html"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/iframe2.html", "text/html"));
+}
+
+// Test that when serializing a page, all CSS resources are reported, including url()'s
+// and imports and links. Note that we don't test the resources contents, we only make sure
+// they are all reported with the right mime type and that they contain some data.
+TEST_F(WebPageNewSerializeTest, FAILS_CSSResources)
+{
+    // Register the mocked frame and load it.
+    WebURL topFrameURL = setUpCSSTestPage();
+    loadURLInTopFrame(topFrameURL);
+
+    WebVector<WebPageSerializer::Resource> resources;
+    WebPageSerializer::serialize(m_webView, &resources);
+    ASSERT_FALSE(resources.isEmpty());
+
+    // The first resource should be the main-frame.
+    const WebPageSerializer::Resource& resource = resources[0];
+    EXPECT_TRUE(resource.url == WebURL(toKURL("http://www.test.com")));
+    EXPECT_EQ(0, resource.mimeType.compare(WebCString("text/html")));
+    EXPECT_FALSE(resource.data.isEmpty());
+
+    EXPECT_EQ(12U, resources.size()); // There should be no duplicates.
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/link_styles.css", "text/css"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/import_styles.css", "text/css"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/import_style_from_link.css", "text/css"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/red_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/orange_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/yellow_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/green_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/blue_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/purple_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/ul-dot.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/ol-dot.png", "image/png"));
+}
+
+// Tests that when serializing a page with blank frames these are reported with their resources.
+TEST_F(WebPageNewSerializeTest, BlankFrames)
+{
+    // Register the mocked frame and load it.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad(topFrameURL, WebString::fromUTF8("blank_frames.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/red_background.png"), WebString::fromUTF8("red_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/orange_background.png"), WebString::fromUTF8("orange_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+    registerMockedURLLoad(toKURL("http://www.test.com/blue_background.png"), WebString::fromUTF8("blue_background.png"), WebString::fromUTF8("pageserializer/"), pngMimeType());
+
+    loadURLInTopFrame(topFrameURL);
+
+    WebVector<WebPageSerializer::Resource> resources;
+    WebPageSerializer::serialize(m_webView, &resources);
+    ASSERT_FALSE(resources.isEmpty());
+
+    // The first resource should be the main-frame.
+    const WebPageSerializer::Resource& resource = resources[0];
+    EXPECT_TRUE(resource.url == WebURL(toKURL("http://www.test.com")));
+    EXPECT_EQ(0, resource.mimeType.compare(WebCString("text/html")));
+    EXPECT_FALSE(resource.data.isEmpty());
+
+    EXPECT_EQ(7U, resources.size()); // There should be no duplicates.
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/red_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/orange_background.png", "image/png"));
+    EXPECT_TRUE(resourceVectorContains(resources, "http://www.test.com/blue_background.png", "image/png"));
+    // The blank frames should have got a magic URL.
+    EXPECT_TRUE(resourceVectorContains(resources, "wyciwyg://frame/0", "text/html"));
+    EXPECT_TRUE(resourceVectorContains(resources, "wyciwyg://frame/1", "text/html"));
+    EXPECT_TRUE(resourceVectorContains(resources, "wyciwyg://frame/2", "text/html"));
+}
+
+TEST_F(WebPageNewSerializeTest, SerializeXMLHasRightDeclaration)
+{
+    WebURL topFrameURL = toKURL("http://www.test.com/simple.xhtml");
+    registerMockedURLLoad(topFrameURL, WebString::fromUTF8("simple.xhtml"), WebString::fromUTF8("pageserializer/"), xhtmlMimeType());
+
+    loadURLInTopFrame(topFrameURL);
+
+    WebVector<WebPageSerializer::Resource> resources;
+    WebPageSerializer::serialize(m_webView, &resources);
+    ASSERT_FALSE(resources.isEmpty());
+
+    // We expect only one resource, the XML.
+    ASSERT_EQ(1U, resources.size());
+    std::string xml = std::string(resources[0].data.data());
+
+    // We should have one and only one instance of the XML declaration.
+    size_t pos = xml.find("<?xml version=");
+    ASSERT_TRUE(pos != std::string::npos);
+
+    pos = xml.find("<?xml version=", pos + 1);
+    ASSERT_TRUE(pos == std::string::npos);
+}
+
+TEST_F(WebPageNewSerializeTest, FAILS_TestMHTMLEncoding)
+{
+    // Load a page with some CSS and some images.
+    WebURL topFrameURL = setUpCSSTestPage();
+    loadURLInTopFrame(topFrameURL);
+
+    WebCString mhtmlData = WebPageSerializer::serializeToMHTML(m_webView);
+    ASSERT_FALSE(mhtmlData.isEmpty());
+
+    // Read the MHTML data line per line and do some pseudo-parsing to make sure the right encoding is used for the different sections.
+    LineReader lineReader(std::string(mhtmlData.data()));
+    int sectionCheckedCount = 0;
+    const char* expectedEncoding = 0;
+    std::string line;
+    while (lineReader.getNextLine(&line)) {
+        if (!line.find("Content-Type:")) {
+            ASSERT_FALSE(expectedEncoding);
+            if (line.find("multipart/related;") != std::string::npos) {
+                // Skip this one, it's part of the MHTML header.
+                continue;
+            }
+            if (line.find("text/") != std::string::npos)
+                expectedEncoding = "quoted-printable";
+            else if (line.find("image/") != std::string::npos)
+                expectedEncoding = "base64";
+            else
+                FAIL() << "Unexpected Content-Type: " << line;
+            continue;
+        }
+        if (!line.find("Content-Transfer-Encoding:")) {
+           ASSERT_TRUE(expectedEncoding);
+           EXPECT_TRUE(line.find(expectedEncoding) != std::string::npos);
+           expectedEncoding = 0;
+           sectionCheckedCount++;
+        }
+    }
+    EXPECT_EQ(12, sectionCheckedCount);
+}
+
+// Test that we don't regress https://bugs.webkit.org/show_bug.cgi?id=99105
+TEST_F(WebPageNewSerializeTest, SVGImageDontCrash)
+{
+    WebURL pageUrl = toKURL("http://www.test.com");
+    WebURL imageUrl = toKURL("http://www.test.com/green_rectangle.svg");
+
+    registerMockedURLLoad(pageUrl, WebString::fromUTF8("page_with_svg_image.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    registerMockedURLLoad(imageUrl, WebString::fromUTF8("green_rectangle.svg"), WebString::fromUTF8("pageserializer/"), svgMimeType());
+
+    loadURLInTopFrame(pageUrl);
+
+    WebCString mhtml = WebPageSerializer::serializeToMHTML(m_webView);
+    // We expect some data to be generated.
+    EXPECT_GT(mhtml.length(), 50U);
+}
+
+TEST_F(WebPageNewSerializeTest, NamespaceElementsDontCrash)
+{
+    WebURL pageUrl = toKURL("http://www.test.com");
+    registerMockedURLLoad(pageUrl, WebString::fromUTF8("namespace_element.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+
+    loadURLInTopFrame(pageUrl);
+
+    WebVector<WebURL> localLinks(static_cast<size_t>(1));
+    WebVector<WebString> localPaths(static_cast<size_t>(1));
+    localLinks[0] = pageUrl;
+    localPaths[0] = WebString("/");
+
+    size_t counter = 0;
+    LengthCountingWebPageSerializerClient client(&counter);
+
+    // We just want to make sure nothing crazy happens, namely that no
+    // assertions are hit. As a sanity check, we also make sure that some data
+    // was returned.
+    WebPageSerializer::serialize(m_webView->mainFrame(), true, &client, localLinks, localPaths, WebString(""));
+
+    EXPECT_GT(counter, 0U);
+}
+
+}
+
+TEST_F(WebPageNewSerializeTest, TestMHTMLEncodingWithDataURL)
+{
+    // Load a page with some data urls.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad(topFrameURL, WebString::fromUTF8("page_with_data.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    loadURLInTopFrame(topFrameURL);
+
+    WebCString mhtmlData = WebPageSerializer::serializeToMHTML(m_webView);
+    ASSERT_FALSE(mhtmlData.isEmpty());
+
+    // Read the MHTML data line and check that the string data:image is found
+    // exactly one time.
+    size_t nbDataURLs = 0;
+    LineReader lineReader(std::string(mhtmlData.data()));
+    std::string line;
+    while (lineReader.getNextLine(&line)) {
+        if (line.find("data:image") != std::string::npos)
+            nbDataURLs++;
+    }
+    EXPECT_EQ(1u, nbDataURLs);
+}
+
+
+TEST_F(WebPageNewSerializeTest, TestMHTMLEncodingWithMorphingDataURL)
+{
+    // Load a page with some data urls.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad(topFrameURL, WebString::fromUTF8("page_with_morphing_data.html"), WebString::fromUTF8("pageserializer/"), htmlMimeType());
+    loadURLInTopFrame(topFrameURL);
+
+    WebCString mhtmlData = WebPageSerializer::serializeToMHTML(m_webView);
+    ASSERT_FALSE(mhtmlData.isEmpty());
+
+    // Read the MHTML data line and check that the string data:image is found
+    // exactly two times.
+    size_t nbDataURLs = 0;
+    LineReader lineReader(std::string(mhtmlData.data()));
+    std::string line;
+    while (lineReader.getNextLine(&line)) {
+        if (line.find("data:text") != std::string::npos)
+            nbDataURLs++;
+    }
+    EXPECT_EQ(2u, nbDataURLs);
+}
```


### `third_party/WebKit/Source/web/tests/WebPageSerializerTest.cpp`

```diff
@@ -0,0 +1,193 @@
+/*
+ * Copyright (C) 2011 Google Inc. All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are
+ * met:
+ *
+ *     * Redistributions of source code must retain the above copyright
+ * notice, this list of conditions and the following disclaimer.
+ *     * Redistributions in binary form must reproduce the above
+ * copyright notice, this list of conditions and the following disclaimer
+ * in the documentation and/or other materials provided with the
+ * distribution.
+ *     * Neither the name of Google Inc. nor the names of its
+ * contributors may be used to endorse or promote products derived from
+ * this software without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+ * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+ * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+ * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+ * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+ * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+ * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+ * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+ * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "config.h"
+#include "WebPageSerializer.h"
+
+#include "URLTestHelpers.h"
+#include "WebFrame.h"
+#include "WebFrameClient.h"
+#include "WebView.h"
+#include "public/platform/Platform.h"
+#include "public/platform/WebString.h"
+#include "public/platform/WebURL.h"
+#include "public/platform/WebURLRequest.h"
+#include "public/platform/WebURLResponse.h"
+#include "public/platform/WebUnitTestSupport.h"
+
+#include <gtest/gtest.h>
+
+using namespace blink;
+using blink::URLTestHelpers::toKURL;
+
+namespace {
+
+class TestWebFrameClient : public WebFrameClient {
+};
+
+class WebPageSerializerTest : public testing::Test {
+public:
+    WebPageSerializerTest() : m_webView(0), m_supportedSchemes(static_cast<size_t>(3))
+    {
+        m_supportedSchemes[0] = "http";
+        m_supportedSchemes[1] = "https";
+        m_supportedSchemes[2] = "file";
+    }
+
+protected:
+    virtual void SetUp()
+    {
+        // Create and initialize the WebView.
+        m_webView = WebView::create(0);
+        m_mainFrame = WebFrame::create(&m_webFrameClient);
+        m_webView->setMainFrame(m_mainFrame);
+    }
+
+    virtual void TearDown()
+    {
+        Platform::current()->unitTestSupport()->unregisterAllMockedURLs();
+        m_webView->close();
+        m_mainFrame->close();
+    }
+
+    void registerMockedURLLoad(const std::string& url, const WebString& fileName)
+    {
+        URLTestHelpers::registerMockedURLLoad(toKURL(url), fileName, WebString::fromUTF8("pageserialization/"), WebString::fromUTF8("text/html"));
+    }
+
+    void loadURLInTopFrame(const WebURL& url)
+    {
+        WebURLRequest urlRequest;
+        urlRequest.initialize();
+        urlRequest.setURL(url);
+        m_webView->mainFrame()->loadRequest(urlRequest);
+        // Make sure any pending request get served.
+        Platform::current()->unitTestSupport()->serveAsynchronousMockedRequests();
+    }
+
+    static bool webVectorContains(const WebVector<WebURL>& vector, const char* url)
+    {
+        return vector.contains(WebURL(toKURL(std::string(url))));
+    }
+
+    // Useful for debugging.
+    static void printWebURLs(const WebVector<WebURL>& urls)
+    {
+        for (size_t i = 0; i < urls.size(); i++)
+            printf("%s\n", urls[i].spec().data());
+    }
+
+    WebView* m_webView;
+    WebVector<WebCString> m_supportedSchemes;
+
+private:
+    TestWebFrameClient m_webFrameClient;
+    WebFrame* m_mainFrame;
+};
+
+TEST_F(WebPageSerializerTest, HTMLNodes)
+{
+    // Register the mocked frame and load it.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad("http://www.test.com", WebString::fromUTF8("simple_page.html"));
+    registerMockedURLLoad("http://www.example.com/beautifull.css", WebString::fromUTF8("beautifull.css"));
+    loadURLInTopFrame(topFrameURL);
+
+    // Retrieve all resources.
+    WebVector<WebURL> frames;
+    WebVector<WebURL> resources;
+    ASSERT_TRUE(WebPageSerializer::retrieveAllResources(
+        m_webView, m_supportedSchemes, &resources, &frames));
+
+    // Tests that all resources from the frame have been retrieved.
+    EXPECT_EQ(1U, frames.size()); // There should be no duplicates.
+    EXPECT_TRUE(webVectorContains(frames, "http://www.test.com"));
+
+    EXPECT_EQ(14U, resources.size()); // There should be no duplicates.
+    EXPECT_TRUE(webVectorContains(resources, "http://www.example.com/beautifull.css"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/awesome.js"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/bodyBackground.jpg"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/awesome.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/imageButton.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/tableBackground.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/trBackground.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/tdBackground.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.evene.fr/citations/auteur.php?ida=46"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.brainyquote.com/quotes/authors/c/charles_darwin.html"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/why_deleted.html"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/why_inserted.html"));
+    EXPECT_TRUE(webVectorContains(resources, "https://www.secure.com/https.gif"));
+    EXPECT_TRUE(webVectorContains(resources, "file://c/my_folder/file.gif"));
+}
+
+TEST_F(WebPageSerializerTest, MultipleFrames)
+{
+    // Register the mocked frames.
+    WebURL topFrameURL = toKURL("http://www.test.com");
+    registerMockedURLLoad("http://www.test.com", WebString::fromUTF8("top_frame.html"));
+    registerMockedURLLoad("http://www.test.com/simple_iframe.html",
+                          WebString::fromUTF8("simple_iframe.html"));
+    registerMockedURLLoad("http://www.test.com/object_iframe.html",
+                          WebString::fromUTF8("object_iframe.html"));
+    registerMockedURLLoad("http://www.test.com/embed_iframe.html",
+                          WebString::fromUTF8("embed_iframe.html"));
+    // If we don't register a mocked resource for awesome.png, it causes the
+    // document loader of the iframe that has it as its src to assert on close,
+    // not sure why.
+    registerMockedURLLoad("http://www.test.com/awesome.png",
+                          WebString::fromUTF8("awesome.png"));
+
+    loadURLInTopFrame(topFrameURL);
+
+    // Retrieve all resources.
+    WebVector<WebURL> frames;
+    WebVector<WebURL> resources;
+    ASSERT_TRUE(WebPageSerializer::retrieveAllResources(
+        m_webView, m_supportedSchemes, &resources, &frames));
+
+    // Tests that all resources from the frame have been retrieved.
+    EXPECT_EQ(4U, frames.size()); // There should be no duplicates.
+    EXPECT_TRUE(webVectorContains(frames, "http://www.test.com"));
+    EXPECT_TRUE(webVectorContains(frames, "http://www.test.com/simple_iframe.html"));
+    EXPECT_TRUE(webVectorContains(frames, "http://www.test.com/object_iframe.html"));
+    EXPECT_TRUE(webVectorContains(frames, "http://www.test.com/embed_iframe.html"));
+
+    EXPECT_EQ(5U, resources.size()); // There should be no duplicates.
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/awesome.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/innerFrame.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/flash.swf"));
+    // FIXME: for some reason the following resources is missing on one of the bot
+    //        causing the test to fail. Probably a plugin issue.
+    // EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/music.mid"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/object.png"));
+    EXPECT_TRUE(webVectorContains(resources, "http://www.test.com/embed.png"));
+}
+
+}
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/awesome.png`

```diff
@@ -0,0 +1 @@
+
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/beautifull.css`

```diff
@@ -0,0 +1 @@
+/* placeholder */
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/embed_iframe.html`

```diff
@@ -1,3 +1,5 @@
 <html>
+
 <img src="embed.png"/>
+
 </html>
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/object_iframe.html`

```diff
@@ -1,3 +1,5 @@
 <html>
+
 <img src="object.png"/>
+
 </html>
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/simple_iframe.html`

```diff
@@ -0,0 +1,14 @@
+<html>
+<!--
+    This page is used to test that WebPageSerializer::retrieveAllResources retrieves
+    correctly the expected resources when dealing with multiple frames. 
+-->
+
+<body>
+
+<img src="awesome.png"/>
+<img src="innerFrame.png"/>
+
+</body>
+
+</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/simple_page.html`

```diff
@@ -0,0 +1,50 @@
+<html>
+<!--
+    This page is used to test that WebPageSerializer::retrieveAllResources retrieves
+    correctly the expected resources from various HTML nodes.
+-->
+
+<head>
+<!-- Style sheet links should be retrieved -->
+<link rel="stylesheet" type="text/css" href="http://www.example.com/beautifull.css"/>
+<!-- Other link should NOT be retrieved -->
+<link rel="copyright" type="text/plain" href="http://www.example.com/copyright"/>
+<!-- Scripts should be retrieved -->
+<script src="awesome.js"></script>
+</head>
+
+<!-- Images are always retrieved -->
+<body background="bodyBackground.jpg">
+
+<!-- Twice to make sure we only report each resource once -->
+<img src="awesome.png"/>
+<img src="awesome.png"/>
+
+<form>
+  <input type="image" src="imageButton.png"/>
+</form>
+
+<table background="tableBackground.png">
+  <tr background="trBackground.png">
+    <td background="tdBackground.png"></td>
+  </tr>  
+  <tr background="trBackground.png">
+    <td background="tdBackground.png"></td>
+  </tr>
+</table>
+
+<!-- Some more obscure tags -->
+<blockquote cite="http://www.evene.fr/citations/auteur.php?ida=46"></blockquote>
+<q CITE="http://www.brainyquote.com/quotes/authors/c/charles_darwin.html"></q>
+<p>My favorite color is <del cite="why_deleted.html">blue</del> <ins>red</ins>!</p>
+<p>My favorite color is <del>blue</del> <ins cite="why_inserted.html">red</ins>!</p>
+
+<!-- Make sure we only retrieve URLs with the right schemes -->
+<img src="https://www.secure.com/https.gif"/>  <!-- HTTPS is OK -->
+<img src="file://c/my_folder/file.gif"/>  <!-- file is OK -->
+<img src="ftp://ftp.com/ftp.gif"/>  <!-- FTP is not OK -->
+<img src="unknown://unkown.com/unknown.gif"/>  <!-- Unknown schemes are not OK -->
+
+</body>
+
+</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserialization/top_frame.html`

```diff
@@ -0,0 +1,28 @@
+<html>
+<!--
+    This page is used to test that WebPageSerializer::retrieveAllResources retrieves
+    correctly the expected resources when dealing with multiple frames. 
+-->
+
+<body>
+
+<!-- Resources used by a frame and a tag should be only reported once -->
+<iframe src="awesome.png"></iframe>
+<img src="awesome.png"/>
+
+<iframe src="simple_iframe.html"></iframe>
+<iframe src="simple_iframe.html"></iframe>
+
+<!-- Object tags can be used to create iframes -->
+
+<object data="object_iframe.html"></object>
+<object data="flash.swf"></object>
+
+<!-- Embed tags can be used to create iframes as well -->
+<embed src="embed_iframe.html"></object>
+<!--
+<embed src="music.mid"></embed>
+-->
+</body>
+
+</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/blank_frames.html`

```diff
@@ -1,7 +1,5 @@
-<!-- This page is used to test that blank frames with dynamic contents are 
-     correctly serialized by the PageSerializer.
--->
 <html>
+
 <script>
   function onload() {
     var frame = document.createElement("iframe");
@@ -26,11 +24,14 @@
       "Some text<br>An image <img src='orange_background.png'.><br><b>Some more text</b>"
 
   }
+  
 </script>
+
 <body onload="onload()">
   This page creates empty iframes and adds content to them dynamically.<br><br>
   <div id="myDiv1"></div>
   <div id="myDiv2"></div>
   <div id="myDiv3"></div>
 </body>
+
 </html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/css_test_page.html`

```diff
@@ -1,7 +1,9 @@
-<!-- This page is used to test that CSS resources are retrieved correctly by
-     the PageSerializer.
--->
 <html>
+
+<!-- This page is used to test that CSS resources are retrieved correctly by the
+     WebPageSerializer::generateSnapshot method
+-->
+
 <head>
 
 <link rel="stylesheet" type="text/css" href="link_styles.css" />
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/datauri/page_with_data.html`

```diff
@@ -1,10 +0,0 @@
-<!--
-  This page is used to test that PageSerializer does not unnecessarily create
-  resources for data URLs.
--->
-<html>
-<body>
-<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAAXNSR0IArs4c6QAAAAxJREFUCNdjYGBgAAAABAABJzQnCgAAAABJRU5ErkJggg=="/>
-<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAAXNSR0IArs4c6QAAAAxJREFUCNdjYGBgAAAABAABJzQnCgAAAABJRU5ErkJggg=="/>
-</body>
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/dtd/dtd.html`

```diff
@@ -2,9 +2,9 @@
 <html lang="en">
  <head>
   <meta charset="utf-8"/>
-  <title>HTML5 DTD Test Page</title>
+  <title>DTD Test Page</title>
 </head>
  <body>
-  <p>HTML5 DTD Test Page</p>
+  <p>DTD Test Page</p>
  </body>
 </html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/elements/elements.html`

```diff
@@ -1,45 +0,0 @@
-<!-- This page is used to test that PageSerializer correctly serializes the
-     expected resources from various HTML nodes.
--->
-<html>
-<head>
-<!-- Style sheet links should be retrieved -->
-<link rel="stylesheet" type="text/css" href="style.css"/>
-<!-- Other link should NOT be retrieved -->
-<link rel="copyright" type="text/plain" href="copyright.html"/>
-<!-- Scripts should NOT be retrieved -->
-<script src="script.js"></script>
-</head>
-
-<!-- Images are always retrieved -->
-<body background="bodyBackground.png">
-
-<!-- Twice to make sure we only report each resource once -->
-<img src="imageSrc.png"/>
-<img src="imageSrc.png"/>
-
-<!-- Non existing resource, should NOT be serialized -->
-<img src="nonExisting.png"/>
-
-<form>
-  <input type="image" src="inputImage.png"/>
-</form>
-
-<table background="tableBackground.png">
-  <tr background="trBackground.png">
-    <td background="tdBackground.png"></td>
-  </tr>  
-  <tr background="trBackground.png">
-    <td background="tdBackground.png"></td>
-  </tr>
-</table>
-
-<!-- Some more obscure tags, should NOT be serialized -->
-<blockquote cite="blockquoteCite.html"></blockquote>
-<q cite="qCite.html"></q>
-<p>My favorite color is <del cite="delCite.html">blue</del> <ins>red</ins>!</p>
-<p>My favorite color is <del>blue</del> <ins cite="insCite.html">red</ins>!</p>
-
-</body>
-
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/elements/style.css`

```diff
@@ -1,3 +0,0 @@
-body {
-  background-color: #f00;
-}
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/elements/text.txt`

```diff
@@ -1 +0,0 @@
-Empty
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames.html`

```diff
@@ -1,14 +0,0 @@
-<!-- This page is used to test that the PageSerializer correctly retrieves
-     resources in frames and framesets.
--->
-<html>
-
-<frameset rows="50%,50%">
-  <frame src="simple_frames_top.html">
-  <frameset cols="25%,75%">
-    <frame src="simple_frames_3.html">
-    <frame src="frame_4.png">
-  </frameset>
-</frameset>
-
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_1.html`

```diff
@@ -1,3 +0,0 @@
-<html>
-<img src="frame_1.png"/>
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_3.html`

```diff
@@ -1,3 +0,0 @@
-<html>
-<img src="frame_3.png"/>
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_frames_top.html`

```diff
@@ -1,7 +0,0 @@
-<html>
-<frameset cols="75%,25%">
-    <frame src="simple_frames_1.html">
-    <frame src="frame_2.png">
-  </frameset>
-</frameset>
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/frames/simple_iframe.html`

```diff
@@ -1,5 +0,0 @@
-<html>
-<body>
-<img src="simple.png"/>
-</body>
-</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/iframe.html`

```diff
@@ -0,0 +1,9 @@
+<html>
+<body>
+
+<img src="blue_background.png"/>
+<img src="red_background.png"/>
+
+</body>
+
+</html>
```


### `third_party/WebKit/Source/web/tests/data/pageserializer/iframe2.html`

```diff
@@ -0,0 +1,9 @@
+<html>
+<body>
+
+<img src="green_background.png"/>
+<img src="blue_background.png"/>
+
+</body>
+
+</html>
```


_[32 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
