# Pacote de anotacao — caso 42

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

# Evidencia do caso 42

## Identificacao

- projeto: Chrome
- CVE: CVE-2011-2794
- CWE atribuida pelo BigVul: CWE-119
- commit: `3057be01bcbbd1d0938afb489e18f2ca6d9b8229`
- URL do commit: https://github.com/chromium/chromium/commit/3057be01bcbbd1d0938afb489e18f2ca6d9b8229
- arquivo da funcao marcada: `third_party/WebKit/Source/WebKit/blackberry/WebKitSupport/InRegionScrollableArea.cpp`

## Mensagem do commit

> Remove minimum and maximum scroll position as they are no
> longer required due to changes in ScrollViewBase.
> https://bugs.webkit.org/show_bug.cgi?id=87298
> 
> Patch by Genevieve Mak <gmak@rim.com> on 2012-05-23
> Reviewed by Antonio Gomes.
> 
> * WebKitSupport/InRegionScrollableArea.cpp:
> (BlackBerry::WebKit::InRegionScrollableArea::InRegionScrollableArea):
> * WebKitSupport/InRegionScrollableArea.h:
> (InRegionScrollableArea):
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@118233 bbb929c8-8fbe-4397-9dbb-9b2b20218538

## Resumo da CVE

> Google Chrome before 13.0.782.107 does not properly perform text iteration, which allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,6 +1 @@
 Platform::IntPoint InRegionScrollableArea::calculateMinimumScrollPosition(const Platform::IntSize& viewportSize, float overscrollLimitFactor) const
-{
-    ASSERT(!allowsOverscroll());
-    return Platform::IntPoint(-(viewportSize.width() * overscrollLimitFactor),
-                              -(viewportSize.height() * overscrollLimitFactor));
-}
```

## Corpo completo da funcao antes da correcao

```c
Platform::IntPoint InRegionScrollableArea::calculateMinimumScrollPosition(const Platform::IntSize& viewportSize, float overscrollLimitFactor) const
{
    ASSERT(!allowsOverscroll());
    return Platform::IntPoint(-(viewportSize.width() * overscrollLimitFactor),
                              -(viewportSize.height() * overscrollLimitFactor));
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/WebKit/Source/WebKit/blackberry/ChangeLog` | modified | 13 | 0 |
| `third_party/WebKit/Source/WebKit/blackberry/WebKitSupport/InRegionScrollableArea.cpp` **(funcao marcada esta aqui)** | modified | 2 | 33 |
| `third_party/WebKit/Source/WebKit/blackberry/WebKitSupport/InRegionScrollableArea.h` | modified | 0 | 3 |


### `third_party/WebKit/Source/WebKit/blackberry/WebKitSupport/InRegionScrollableArea.cpp`

```diff
@@ -70,14 +70,7 @@ InRegionScrollableArea::InRegionScrollableArea(WebPagePrivate* webPage, RenderLa
         m_scrollsHorizontally = view->contentsWidth() > view->visibleWidth();
         m_scrollsVertically = view->contentsHeight() > view->visibleHeight();
 
-        m_minimumScrollPosition = m_webPage->mapToTransformed(calculateMinimumScrollPosition(
-            view->visibleContentRect().size(),
-            0.0 /*overscrollLimit*/));
-        m_maximumScrollPosition = m_webPage->mapToTransformed(calculateMaximumScrollPosition(
-            view->visibleContentRect().size(),
-            view->contentsSize(),
-            0.0 /*overscrollLimit*/));
-
+        m_overscrollLimitFactor = 0.0; // FIXME eventually support overscroll
     } else { // RenderBox-based elements case (scrollable boxes (div's, p's, textarea's, etc)).
 
         RenderBox* box = m_layer->renderBox();
@@ -100,34 +93,10 @@ InRegionScrollableArea::InRegionScrollableArea(WebPagePrivate* webPage, RenderLa
         m_scrollsHorizontally = box->scrollWidth() != box->clientWidth() && box->scrollsOverflowX();
         m_scrollsVertically = box->scrollHeight() != box->clientHeight() && box->scrollsOverflowY();
 
-        m_minimumScrollPosition = m_webPage->mapToTransformed(calculateMinimumScrollPosition(
-            Platform::IntSize(box->clientWidth(), box->clientHeight()),
-            0.0 /*overscrollLimit*/));
-        m_maximumScrollPosition = m_webPage->mapToTransformed(calculateMaximumScrollPosition(
-            Platform::IntSize(box->clientWidth(), box->clientHeight()),
-            Platform::IntSize(box->scrollWidth(), box->scrollHeight()),
-            0.0 /*overscrollLimit*/));
+        m_overscrollLimitFactor = 0.0; // FIXME eventually support overscroll
     }
 }
 
-Platform::IntPoint InRegionScrollableArea::calculateMinimumScrollPosition(const Platform::IntSize& viewportSize, float overscrollLimitFactor) const
-{
-    // FIXME: Eventually we should support overscroll like iOS5 does.
-    ASSERT(!allowsOverscroll());
-
-    return Platform::IntPoint(-(viewportSize.width() * overscrollLimitFactor),
-                              -(viewportSize.height() * overscrollLimitFactor));
-}
-
-Platform::IntPoint InRegionScrollableArea::calculateMaximumScrollPosition(const Platform::IntSize& viewportSize, const Platform::IntSize& contentsSize, float overscrollLimitFactor) const
-{
-    // FIXME: Eventually we should support overscroll like iOS5 does.
-    ASSERT(!allowsOverscroll());
-
-    return Platform::IntPoint(std::max(contentsSize.width() - viewportSize.width(), 0) + overscrollLimitFactor,
-                              std::max(contentsSize.height() - viewportSize.height(), 0) + overscrollLimitFactor);
-}
-
 RenderLayer* InRegionScrollableArea::layer() const
 {
     ASSERT(!m_isNull);
```


### `third_party/WebKit/Source/WebKit/blackberry/ChangeLog`

```diff
@@ -1,3 +1,16 @@
+2012-05-23  Genevieve Mak  <gmak@rim.com>
+
+        Remove minimum and maximum scroll position as they are no
+        longer required due to changes in ScrollViewBase.
+        https://bugs.webkit.org/show_bug.cgi?id=87298
+
+        Reviewed by Antonio Gomes.
+
+        * WebKitSupport/InRegionScrollableArea.cpp:
+        (BlackBerry::WebKit::InRegionScrollableArea::InRegionScrollableArea):
+        * WebKitSupport/InRegionScrollableArea.h:
+        (InRegionScrollableArea):
+
 2012-05-22  Chris Guan  <chris.guan@torchmobile.com.cn>
 
         [Blackberry]Pages contain video or audio tags should be in pageCache
```


### `third_party/WebKit/Source/WebKit/blackberry/WebKitSupport/InRegionScrollableArea.h`

```diff
@@ -40,9 +40,6 @@ class InRegionScrollableArea : public Platform::ScrollViewBase {
     WebCore::RenderLayer* layer() const;
 
 private:
-    Platform::IntPoint calculateMinimumScrollPosition(const Platform::IntSize& viewportSize, float overscrollLimitFactor) const;
-    Platform::IntPoint calculateMaximumScrollPosition(const Platform::IntSize& viewportSize, const Platform::IntSize& contentsSize, float overscrollLimitFactor) const;
-
     WebPagePrivate* m_webPage;
     WebCore::RenderLayer* m_layer;
 };
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
