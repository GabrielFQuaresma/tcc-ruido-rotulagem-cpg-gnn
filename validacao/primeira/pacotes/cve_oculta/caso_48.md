# Pacote de anotacao — caso 48

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

# Evidencia do caso 48

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `third_party/WebKit/Source/WebCore/css/CSSComputedStyleDeclaration.cpp`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -29,8 +29,9 @@
          return cssValuePool().createValue(l);
      }
  
-    if (style->position() == RelativePosition)
+    if (style->position() == RelativePosition) {
          return cssValuePool().createValue(l);
+    }
  
      return cssValuePool().createIdentifierValue(CSSValueAuto);
  }
```

## Corpo completo da funcao antes da correcao

```c
static PassRefPtr<CSSValue> getPositionOffsetValue(RenderStyle* style, CSSPropertyID propertyID, RenderView* renderView)
{
    if (!style)
        return 0;

    Length l;
    switch (propertyID) {
        case CSSPropertyLeft:
            l = style->left();
            break;
        case CSSPropertyRight:
            l = style->right();
            break;
        case CSSPropertyTop:
            l = style->top();
            break;
        case CSSPropertyBottom:
            l = style->bottom();
            break;
        default:
            return 0;
    }

    if (style->position() == AbsolutePosition || style->position() == FixedPosition) {
        if (l.type() == WebCore::Fixed)
            return zoomAdjustedPixelValue(l.value(), style);
        else if (l.isViewportPercentage())
            return zoomAdjustedPixelValue(valueForLength(l, 0, renderView), style);
         return cssValuePool().createValue(l);
     }
 
    if (style->position() == RelativePosition)
         return cssValuePool().createValue(l);
 
     return cssValuePool().createIdentifierValue(CSSValueAuto);
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **39**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/WebKit/Source/WebCore/ChangeLog` | modified | 184 | 0 |
| `third_party/WebKit/Source/WebCore/css/CSSComputedStyleDeclaration.cpp` **(funcao marcada esta aqui)** | modified | 2 | 1 |
| `third_party/WebKit/Source/WebCore/css/StyleResolver.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/dom/Text.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/editing/DeleteButtonController.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/editing/TextIterator.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/AutoTableLayout.cpp` | modified | 2 | 2 |
| `third_party/WebKit/Source/WebCore/rendering/InlineFlowBox.cpp` | modified | 11 | 11 |
| `third_party/WebKit/Source/WebCore/rendering/InlineIterator.h` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/LayoutState.cpp` | modified | 2 | 2 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBlock.cpp` | modified | 46 | 47 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBlock.h` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBlockLineLayout.cpp` | modified | 10 | 10 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBox.cpp` | modified | 31 | 31 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBox.h` | modified | 3 | 3 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBoxModelObject.cpp` | modified | 3 | 3 |
| `third_party/WebKit/Source/WebCore/rendering/RenderBoxModelObject.h` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderDeprecatedFlexibleBox.cpp` | modified | 12 | 8 |
| `third_party/WebKit/Source/WebCore/rendering/RenderFieldset.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderFlexibleBox.cpp` | modified | 11 | 11 |
| `third_party/WebKit/Source/WebCore/rendering/RenderGrid.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderImage.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderInline.cpp` | modified | 8 | 8 |
| `third_party/WebKit/Source/WebCore/rendering/RenderLayer.cpp` | modified | 7 | 7 |
| `third_party/WebKit/Source/WebCore/rendering/RenderLayerCompositor.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderLineBoxList.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderListItem.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderMultiColumnBlock.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderObject.cpp` | modified | 9 | 9 |
| `third_party/WebKit/Source/WebCore/rendering/RenderObject.h` | modified | 4 | 3 |
| `third_party/WebKit/Source/WebCore/rendering/RenderObjectChildList.cpp` | modified | 2 | 2 |
| `third_party/WebKit/Source/WebCore/rendering/RenderReplaced.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderRubyRun.cpp` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebCore/rendering/RenderTable.cpp` | modified | 4 | 4 |
| `third_party/WebKit/Source/WebCore/rendering/style/RenderStyle.h` | modified | 1 | 1 |
| `third_party/WebKit/Source/WebKit/blackberry/Api/WebPage.cpp` | modified | 3 | 3 |
| `third_party/WebKit/Source/WebKit/blackberry/ChangeLog` | modified | 19 | 0 |
| `third_party/WebKit/Source/WebKit2/ChangeLog` | modified | 17 | 0 |
| `third_party/WebKit/Source/WebKit2/WebProcess/WebPage/qt/LayerTreeHostQt.cpp` | modified | 1 | 1 |


### `third_party/WebKit/Source/WebCore/css/CSSComputedStyleDeclaration.cpp`

```diff
@@ -597,11 +597,12 @@ static PassRefPtr<CSSValue> getPositionOffsetValue(RenderStyle* style, CSSProper
         return cssValuePool().createValue(l);
     }
 
-    if (style->position() == RelativePosition)
+    if (style->position() == RelativePosition) {
         // FIXME: It's not enough to simply return "auto" values for one offset if the other side is defined.
         // In other words if left is auto and right is not auto, then left's computed value is negative right().
         // So we should get the opposite length unit and see if it is auto.
         return cssValuePool().createValue(l);
+    }
 
     return cssValuePool().createIdentifierValue(CSSValueAuto);
 }
```


### `third_party/WebKit/Source/WebCore/ChangeLog`

```diff
@@ -1,3 +1,187 @@
+2012-06-24  Simon Fraser  <simon.fraser@apple.com>
+
+        Rename isPositioned to isOutOfFlowPositioned for clarity
+        [url removida]
+
+        Reviewed by Antti Koivisto.
+        
+        RenderObject and RenderStyle had an isPositioned() method that was
+        confusing, because it excluded relative positioning. Rename to 
+        isOutOfFlowPositioned(), which makes it clearer that it only applies
+        to absolute and fixed positioning.
+
+        Simple rename; no behavior change.
+
+        * css/CSSComputedStyleDeclaration.cpp:
+        (WebCore::getPositionOffsetValue):
+        * css/StyleResolver.cpp:
+        (WebCore::StyleResolver::collectMatchingRulesForList):
+        * dom/Text.cpp:
+        (WebCore::Text::rendererIsNeeded):
+        * editing/DeleteButtonController.cpp:
+        (WebCore::isDeletableElement):
+        * editing/TextIterator.cpp:
+        (WebCore::shouldEmitNewlinesBeforeAndAfterNode):
+        * rendering/AutoTableLayout.cpp:
+        (WebCore::shouldScaleColumns):
+        * rendering/InlineFlowBox.cpp:
+        (WebCore::InlineFlowBox::addToLine):
+        (WebCore::InlineFlowBox::placeBoxesInInlineDirection):
+        (WebCore::InlineFlowBox::requiresIdeographicBaseline):
+        (WebCore::InlineFlowBox::adjustMaxAscentAndDescent):
+        (WebCore::InlineFlowBox::computeLogicalBoxHeights):
+        (WebCore::InlineFlowBox::placeBoxesInBlockDirection):
+        (WebCore::InlineFlowBox::flipLinesInBlockDirection):
+        (WebCore::InlineFlowBox::computeOverflow):
+        (WebCore::InlineFlowBox::computeOverAnnotationAdjustment):
+        (WebCore::InlineFlowBox::computeUnderAnnotationAdjustment):
+        * rendering/InlineIterator.h:
+        (WebCore::isIteratorTarget):
+        * rendering/LayoutState.cpp:
+        (WebCore::LayoutState::LayoutState):
+        * rendering/RenderBlock.cpp:
+        (WebCore::RenderBlock::MarginInfo::MarginInfo):
+        (WebCore::RenderBlock::styleWillChange):
+        (WebCore::RenderBlock::styleDidChange):
+        (WebCore::RenderBlock::addChildToContinuation):
+        (WebCore::RenderBlock::addChildToAnonymousColumnBlocks):
+        (WebCore::RenderBlock::containingColumnsBlock):
+        (WebCore::RenderBlock::columnsBlockForSpanningElement):
+        (WebCore::RenderBlock::addChildIgnoringAnonymousColumnBlocks):
+        (WebCore::getInlineRun):
+        (WebCore::RenderBlock::isSelfCollapsingBlock):
+        (WebCore::RenderBlock::layoutBlock):
+        (WebCore::RenderBlock::addOverflowFromBlockChildren):
+        (WebCore::RenderBlock::expandsToEncloseOverhangingFloats):
+        (WebCore::RenderBlock::handlePositionedChild):
+        (WebCore::RenderBlock::moveRunInUnderSiblingBlockIfNeeded):
+        (WebCore::RenderBlock::collapseMargins):
+        (WebCore::RenderBlock::clearFloatsIfNeeded):
+        (WebCore::RenderBlock::simplifiedNormalFlowLayout):
+        (WebCore::RenderBlock::isSelectionRoot):
+        (WebCore::RenderBlock::blockSelectionGaps):
+        (WebCore::RenderBlock::clearFloats):
+        (WebCore::RenderBlock::markAllDescendantsWithFloatsForLayout):
+        (WebCore::RenderBlock::markSiblingsWithFloatsForLayout):
+        (WebCore::isChildHitTestCandidate):
+        (WebCore::InlineMinMaxIterator::next):
+        (WebCore::RenderBlock::computeBlockPreferredLogicalWidths):
+        (WebCore::RenderBlock::firstLineBoxBaseline):
+        (WebCore::RenderBlock::lastLineBoxBaseline):
+        (WebCore::RenderBlock::updateFirstLetter):
+        (WebCore::shouldCheckLines):
+        (WebCore::getHeightForLineCount):
+        (WebCore::RenderBlock::adjustForBorderFit):
+        (WebCore::inNormalFlow):
+        (WebCore::RenderBlock::adjustLinePositionForPagination):
+        (WebCore::RenderBlock::adjustBlockChildForPagination):
+        (WebCore::RenderBlock::renderName):
+        * rendering/RenderBlock.h:
+        (WebCore::RenderBlock::shouldSkipCreatingRunsForObject):
+        * rendering/RenderBlockLineLayout.cpp:
+        (WebCore::RenderBlock::setMarginsForRubyRun):
+        (WebCore::RenderBlock::computeInlineDirectionPositionsForLine):
+        (WebCore::RenderBlock::computeBlockDirectionPositionsForLine):
+        (WebCore::RenderBlock::layoutInlineChildren):
+        (WebCore::requiresLineBox):
+        (WebCore::RenderBlock::LineBreaker::skipTrailingWhitespace):
+        (WebCore::RenderBlock::LineBreaker::skipLeadingWhitespace):
+        (WebCore::RenderBlock::LineBreaker::nextLineBreak):
+        * rendering/RenderBox.cpp:
+        (WebCore::RenderBox::removeFloatingOrPositionedChildFromBlockLists):
+        (WebCore::RenderBox::styleWillChange):
+        (WebCore::RenderBox::styleDidChange):
+        (WebCore::RenderBox::updateBoxModelInfoFromStyle):
+        (WebCore::RenderBox::offsetFromContainer):
+        (WebCore::RenderBox::positionLineBox):
+        (WebCore::RenderBox::computeRectForRepaint):
+        (WebCore::RenderBox::computeLogicalWidthInRegion):
+        (WebCore::RenderBox::renderBoxRegionInfo):
+        (WebCore::RenderBox::computeLogicalHeight):
+        (WebCore::RenderBox::computePercentageLogicalHeight):
+        (WebCore::RenderBox::computeReplacedLogicalWidthUsing):
+        (WebCore::RenderBox::computeReplacedLogicalHeightUsing):
+        (WebCore::RenderBox::availableLogicalHeightUsing):
+        (WebCore::percentageLogicalHeightIsResolvable):
+        * rendering/RenderBox.h:
+        (WebCore::RenderBox::stretchesToViewport):
+        (WebCore::RenderBox::isDeprecatedFlexItem):
+        * rendering/RenderBoxModelObject.cpp:
+        (WebCore::RenderBoxModelObject::adjustedPositionRelativeToOffsetParent):
+        (WebCore::RenderBoxModelObject::mapAbsoluteToLocalPoint):
+        * rendering/RenderBoxModelObject.h:
+        (WebCore::RenderBoxModelObject::requiresLayer):
+        * rendering/RenderDeprecatedFlexibleBox.cpp:
+        (WebCore::childDoesNotAffectWidthOrFlexing):
+        (WebCore::RenderDeprecatedFlexibleBox::layoutBlock):
+        (WebCore::RenderDeprecatedFlexibleBox::layoutHorizontalBox):
+        (WebCore::RenderDeprecatedFlexibleBox::layoutVerticalBox):
+        (WebCore::RenderDeprecatedFlexibleBox::renderName):
+        * rendering/RenderFieldset.cpp:
+        (WebCore::RenderFieldset::findLegend):
+        * rendering/RenderFlexibleBox.cpp:
+        (WebCore::RenderFlexibleBox::computePreferredLogicalWidths):
+        (WebCore::RenderFlexibleBox::autoMarginOffsetInMainAxis):
+        (WebCore::RenderFlexibleBox::availableAlignmentSpaceForChild):
+        (WebCore::RenderFlexibleBox::computeMainAxisPreferredSizes):
+        (WebCore::RenderFlexibleBox::computeNextFlexLine):
+        (WebCore::RenderFlexibleBox::resolveFlexibleLengths):
+        (WebCore::RenderFlexibleBox::prepareChildForPositionedLayout):
+        (WebCore::RenderFlexibleBox::layoutAndPlaceChildren):
+        (WebCore::RenderFlexibleBox::layoutColumnReverse):
+        (WebCore::RenderFlexibleBox::adjustAlignmentForChild):
+        (WebCore::RenderFlexibleBox::flipForRightToLeftColumn):
+        * rendering/RenderGrid.cpp:
+        (WebCore::RenderGrid::renderName):
+        * rendering/RenderImage.cpp:
+        (WebCore::RenderImage::computeIntrinsicRatioInformation):
+        * rendering/RenderInline.cpp:
+        (WebCore::RenderInline::addChildIgnoringContinuation):
+        (WebCore::RenderInline::addChildToContinuation):
+        (WebCore::RenderInline::generateCulledLineBoxRects):
+        (WebCore):
+        (WebCore::RenderInline::culledInlineFirstLineBox):
+        (WebCore::RenderInline::culledInlineLastLineBox):
+        (WebCore::RenderInline::culledInlineVisualOverflowBoundingBox):
+        (WebCore::RenderInline::computeRectForRepaint):
+        (WebCore::RenderInline::dirtyLineBoxes):
+        * rendering/RenderLayer.cpp:
+        (WebCore::checkContainingBlockChainForPagination):
+        (WebCore::RenderLayer::updateLayerPosition):
+        (WebCore::isPositionedContainer):
+        (WebCore::RenderLayer::calculateClipRects):
+        (WebCore::RenderLayer::shouldBeNormalFlowOnly):
+        * rendering/RenderLayerCompositor.cpp:
+        (WebCore::RenderLayerCompositor::requiresCompositingForPosition):
+        * rendering/RenderLineBoxList.cpp:
+        (WebCore::RenderLineBoxList::dirtyLinesFromChangedChild):
+        * rendering/RenderListItem.cpp:
+        (WebCore::getParentOfFirstLineBox):
+        * rendering/RenderMultiColumnBlock.cpp:
+        (WebCore::RenderMultiColumnBlock::renderName):
+        * rendering/RenderObject.cpp:
+        (WebCore::RenderObject::markContainingBlocksForLayout):
+        (WebCore::RenderObject::setPreferredLogicalWidthsDirty):
+        (WebCore::RenderObject::invalidateContainerPreferredLogicalWidths):
+        (WebCore::RenderObject::styleWillChange):
+        (WebCore::RenderObject::offsetParent):
+        * rendering/RenderObject.h:
+        (WebCore::RenderObject::isOutOfFlowPositioned):
+        (WebCore::RenderObject::isInFlowPositioned):
+        (WebCore::RenderObject::hasClip):
+        (WebCore::RenderObject::isFloatingOrOutOfFlowPositioned):
+        * rendering/RenderObjectChildList.cpp:
+        (WebCore::RenderObjectChildList::removeChildNode):
+        * rendering/RenderReplaced.cpp:
+        (WebCore::hasAutoHeightOrContainingBlockWithAutoHeight):
+        * rendering/RenderRubyRun.cpp:
+        (WebCore::RenderRubyRun::rubyText):
+        * rendering/RenderTable.cpp:
+        (WebCore::RenderTable::addChild):
+        (WebCore::RenderTable::computeLogicalWidth):
+        (WebCore::RenderTable::layout):
+        * rendering/style/RenderStyle.h:
+
 2012-06-24  Oli Lan  <olilan@chromium.org>
 
         After Editor::setComposition is called, input should scroll to the end of the composition.
```


### `third_party/WebKit/Source/WebCore/css/StyleResolver.cpp`

```diff
@@ -2076,7 +2076,7 @@ static bool doesNotInheritTextDecoration(RenderStyle* style, Element* e)
 {
     return style->display() == TABLE || style->display() == INLINE_TABLE || style->display() == RUN_IN
         || style->display() == INLINE_BLOCK || style->display() == INLINE_BOX || isAtShadowBoundary(e)
-        || style->isFloating() || style->isPositioned();
+        || style->isFloating() || style->isOutOfFlowPositioned();
 }
 
 void StyleResolver::adjustRenderStyle(RenderStyle* style, RenderStyle* parentStyle, Element *e)
```


### `third_party/WebKit/Source/WebCore/dom/Text.cpp`

```diff
@@ -218,7 +218,7 @@ bool Text::rendererIsNeeded(const NodeRenderingContext& context)
             return false;
         
         RenderObject* first = parent->firstChild();
-        while (first && first->isFloatingOrPositioned())
+        while (first && first->isFloatingOrOutOfFlowPositioned())
             first = first->nextSibling();
         RenderObject* next = context.nextRenderer();
         if (!first || next == first)
```


### `third_party/WebKit/Source/WebCore/editing/DeleteButtonController.cpp`

```diff
@@ -105,7 +105,7 @@ static bool isDeletableElement(const Node* node)
     if (node->hasTagName(ulTag) || node->hasTagName(olTag) || node->hasTagName(iframeTag))
         return true;
 
-    if (renderer->isPositioned())
+    if (renderer->isOutOfFlowPositioned())
         return true;
 
     if (renderer->isRenderBlock() && !renderer->isTableCell()) {
```


### `third_party/WebKit/Source/WebCore/editing/TextIterator.cpp`

```diff
@@ -775,7 +775,7 @@ static bool shouldEmitNewlinesBeforeAndAfterNode(Node* node)
             return true;
     }
     
-    return !r->isInline() && r->isRenderBlock() && !r->isFloatingOrPositioned() && !r->isBody();
+    return !r->isInline() && r->isRenderBlock() && !r->isFloatingOrOutOfFlowPositioned() && !r->isBody();
 }
 
 static bool shouldEmitNewlineAfterNode(Node* node)
```


### `third_party/WebKit/Source/WebCore/rendering/AutoTableLayout.cpp`

```diff
@@ -186,10 +186,10 @@ static bool shouldScaleColumns(RenderTable* table)
     bool scale = true;
     while (table) {
         Length tw = table->style()->width();
-        if ((tw.isAuto() || tw.isPercent()) && !table->isPositioned()) {
+        if ((tw.isAuto() || tw.isPercent()) && !table->isOutOfFlowPositioned()) {
             RenderBlock* cb = table->containingBlock();
             while (cb && !cb->isRenderView() && !cb->isTableCell() &&
-                cb->style()->width().isAuto() && !cb->isPositioned())
+                cb->style()->width().isAuto() && !cb->isOutOfFlowPositioned())
                 cb = cb->containingBlock();
 
             table = 0;
```


### `third_party/WebKit/Source/WebCore/rendering/InlineFlowBox.cpp`

```diff
@@ -119,7 +119,7 @@ void InlineFlowBox::addToLine(InlineBox* child)
             setHasTextDescendantsOnAncestors(this);
     }
 
-    if (descendantsHaveSameLineHeightAndBaseline() && !child->renderer()->isPositioned()) {
+    if (descendantsHaveSameLineHeightAndBaseline() && !child->renderer()->isOutOfFlowPositioned()) {
         RenderStyle* parentStyle = renderer()->style(isFirstLineStyle());
         RenderStyle* childStyle = child->renderer()->style(isFirstLineStyle());
         bool shouldClearDescendantsHaveSameLineHeightAndBaseline = false;
@@ -156,7 +156,7 @@ void InlineFlowBox::addToLine(InlineBox* child)
             clearDescendantsHaveSameLineHeightAndBaseline();
     }
 
-    if (!child->renderer()->isPositioned()) {
+    if (!child->renderer()->isOutOfFlowPositioned()) {
         if (child->isText()) {
             RenderStyle* childStyle = child->renderer()->style(isFirstLineStyle());
             if (childStyle->letterSpacing() < 0 || childStyle->textShadow() || childStyle->textEmphasisMark() != TextEmphasisMarkNone || childStyle->textStrokeWidth())
@@ -391,7 +391,7 @@ float InlineFlowBox::placeBoxesInInlineDirection(float logicalLeft, bool& needsW
             if (knownToHaveNoOverflow())
                 maxLogicalRight = max(logicalLeft, maxLogicalRight);
         } else {
-            if (curr->renderer()->isPositioned()) {
+            if (curr->renderer()->isOutOfFlowPositioned()) {
                 if (curr->renderer()->parent()->style()->isLeftToRightDirection())
                     curr->setLogicalLeft(logicalLeft);
                 else
@@ -445,7 +445,7 @@ bool InlineFlowBox::requiresIdeographicBaseline(const GlyphOverflowAndFallbackFo
         return true;
 
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
         
         if (curr->isInlineFlowBox()) {
@@ -478,7 +478,7 @@ void InlineFlowBox::adjustMaxAscentAndDescent(LayoutUnit& maxAscent, LayoutUnit&
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
         // The computed lineheight needs to be extended for the
         // positioned elements
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
         if (curr->verticalAlign() == TOP || curr->verticalAlign() == BOTTOM) {
             LayoutUnit lineHeight = curr->lineHeight();
@@ -545,7 +545,7 @@ void InlineFlowBox::computeLogicalBoxHeights(RootInlineBox* rootBox, LayoutUnit&
         return;
 
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
         
         InlineFlowBox* inlineFlowBox = curr->isInlineFlowBox() ? toInlineFlowBox(curr) : 0;
@@ -616,7 +616,7 @@ void InlineFlowBox::placeBoxesInBlockDirection(LayoutUnit top, LayoutUnit maxHei
     }
 
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
 
         if (descendantsHaveSameLineHeightAndBaseline()) {
@@ -736,7 +736,7 @@ void InlineFlowBox::flipLinesInBlockDirection(LayoutUnit lineTop, LayoutUnit lin
     setLogicalTop(lineBottom - (logicalTop() - lineTop) - logicalHeight());
     
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders aren't affected here.
         
         if (curr->isInlineFlowBox())
@@ -912,7 +912,7 @@ void InlineFlowBox::computeOverflow(LayoutUnit lineTop, LayoutUnit lineBottom, G
     addBorderOutsetVisualOverflow(logicalVisualOverflow);
 
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
         
         if (curr->renderer()->isText()) {
@@ -1429,7 +1429,7 @@ LayoutUnit InlineFlowBox::computeOverAnnotationAdjustment(LayoutUnit allowedPosi
 {
     LayoutUnit result = 0;
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
         
         if (curr->isInlineFlowBox())
@@ -1477,7 +1477,7 @@ LayoutUnit InlineFlowBox::computeUnderAnnotationAdjustment(LayoutUnit allowedPos
 {
     LayoutUnit result = 0;
     for (InlineBox* curr = firstChild(); curr; curr = curr->nextOnLine()) {
-        if (curr->renderer()->isPositioned())
+        if (curr->renderer()->isOutOfFlowPositioned())
             continue; // Positioned placeholders don't affect calculations.
 
         if (curr->isInlineFlowBox())
```


### `third_party/WebKit/Source/WebCore/rendering/InlineIterator.h`

```diff
@@ -166,7 +166,7 @@ static inline void notifyObserverWillExitObject(Observer* observer, RenderObject
 static inline bool isIteratorTarget(RenderObject* object)
 {
     ASSERT(object); // The iterator will of course return 0, but its not an expected argument to this function.
-    return object->isText() || object->isFloating() || object->isPositioned() || object->isReplaced();
+    return object->isText() || object->isFloating() || object->isOutOfFlowPositioned() || object->isReplaced();
 }
 
 // This enum is only used for bidiNextShared()
```


### `third_party/WebKit/Source/WebCore/rendering/LayoutState.cpp`

```diff
@@ -45,15 +45,15 @@ LayoutState::LayoutState(LayoutState* prev, RenderBox* renderer, const LayoutSiz
 {
     ASSERT(m_next);
 
-    bool fixed = renderer->isPositioned() && renderer->style()->position() == FixedPosition;
+    bool fixed = renderer->isOutOfFlowPositioned() && renderer->style()->position() == FixedPosition;
     if (fixed) {
         // FIXME: This doesn't work correctly with transforms.
         FloatPoint fixedOffset = renderer->view()->localToAbsolute(FloatPoint(), true);
         m_paintOffset = LayoutSize(fixedOffset.x(), fixedOffset.y()) + offset;
     } else
         m_paintOffset = prev->m_paintOffset + offset;
 
-    if (renderer->isPositioned() && !fixed) {
+    if (renderer->isOutOfFlowPositioned() && !fixed) {
         if (RenderObject* container = renderer->container()) {
             if (container->isRelPositioned() && container->isRenderInline())
                 m_paintOffset += toRenderInline(container)->relativePositionedInlineOffset(renderer);
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBlock.cpp`

```diff
@@ -162,7 +162,7 @@ RenderBlock::MarginInfo::MarginInfo(RenderBlock* block, LayoutUnit beforeBorderP
     // if we had any border/padding (obviously), if we're the root or HTML elements, or if
     // we're positioned, floating, a table cell.
     RenderStyle* blockStyle = block->style();
-    m_canCollapseWithChildren = !block->isRenderView() && !block->isRoot() && !block->isPositioned()
+    m_canCollapseWithChildren = !block->isRenderView() && !block->isRoot() && !block->isOutOfFlowPositioned()
         && !block->isFloating() && !block->isTableCell() && !block->hasOverflowClip() && !block->isInlineBlockOrInlineTable()
         && !block->isWritingModeRoot() && blockStyle->hasAutoColumnCount() && blockStyle->hasAutoColumnWidth()
         && !blockStyle->columnSpan();
@@ -278,7 +278,7 @@ void RenderBlock::willBeDestroyed()
 void RenderBlock::styleWillChange(StyleDifference diff, const RenderStyle* newStyle)
 {
     RenderStyle* oldStyle = style();
-    s_canPropagateFloatIntoSibling = oldStyle ? !isFloatingOrPositioned() && !avoidsFloats() : false;
+    s_canPropagateFloatIntoSibling = oldStyle ? !isFloatingOrOutOfFlowPositioned() && !avoidsFloats() : false;
 
     setReplaced(newStyle->isDisplayInlineType());
     
@@ -303,7 +303,7 @@ void RenderBlock::styleWillChange(StyleDifference diff, const RenderStyle* newSt
                 toRenderBlock(cb)->removePositionedObjects(this);
         }
 
-        if (containsFloats() && !isFloating() && !isPositioned() && (newStyle->position() == AbsolutePosition || newStyle->position() == FixedPosition))
+        if (containsFloats() && !isFloating() && !isOutOfFlowPositioned() && (newStyle->position() == AbsolutePosition || newStyle->position() == FixedPosition))
             markAllDescendantsWithFloatsForLayout();
     }
 
@@ -337,7 +337,7 @@ void RenderBlock::styleDidChange(StyleDifference diff, const RenderStyle* oldSty
     // blocks, then we need to find the top most parent containing that overhanging float and
     // then mark its descendants with floats for layout and clear all floats from its next
     // sibling blocks that exist in our floating objects list. See bug 56299 and 62875.
-    bool canPropagateFloatIntoSibling = !isFloatingOrPositioned() && !avoidsFloats();
+    bool canPropagateFloatIntoSibling = !isFloatingOrOutOfFlowPositioned() && !avoidsFloats();
     if (diff == StyleDifferenceLayout && s_canPropagateFloatIntoSibling && !canPropagateFloatIntoSibling && hasOverhangingFloats()) {
         RenderBlock* parentBlock = this;
         const FloatingObjectSet& floatingObjectSet = m_floatingObjects->set();
@@ -412,7 +412,7 @@ void RenderBlock::addChildToContinuation(RenderObject* newChild, RenderObject* b
             beforeChildParent = flow;
     }
 
-    if (newChild->isFloatingOrPositioned()) {
+    if (newChild->isFloatingOrOutOfFlowPositioned()) {
         beforeChildParent->addChildIgnoringContinuation(newChild, beforeChild);
         return;
     }
@@ -459,7 +459,7 @@ void RenderBlock::addChildToAnonymousColumnBlocks(RenderObject* newChild, Render
         beforeChildParent = toRenderBlock(lastChild());
 
     // If the new child is floating or positioned it can just go in that block.
-    if (newChild->isFloatingOrPositioned()) {
+    if (newChild->isFloatingOrOutOfFlowPositioned()) {
         beforeChildParent->addChildIgnoringAnonymousColumnBlocks(newChild, beforeChild);
         return;
     }
@@ -508,7 +508,7 @@ RenderBlock* RenderBlock::containingColumnsBlock(bool allowAnonymousColumnBlock)
 {
     RenderBlock* firstChildIgnoringAnonymousWrappers = 0;
     for (RenderObject* curr = this; curr; curr = curr->parent()) {
-        if (!curr->isRenderBlock() || curr->isFloatingOrPositioned() || curr->isTableCell() || curr->isRoot() || curr->isRenderView() || curr->hasOverflowClip()
+        if (!curr->isRenderBlock() || curr->isFloatingOrOutOfFlowPositioned() || curr->isTableCell() || curr->isRoot() || curr->isRenderView() || curr->hasOverflowClip()
             || curr->isInlineBlockOrInlineTable())
             return 0;
 
@@ -758,7 +758,7 @@ RenderBlock* RenderBlock::columnsBlockForSpanningElement(RenderObject* newChild)
     // This function currently supports (1) and (2).
     RenderBlock* columnsBlockAncestor = 0;
     if (!newChild->isText() && newChild->style()->columnSpan() && !newChild->isBeforeOrAfterContent()
-        && !newChild->isFloatingOrPositioned() && !newChild->isInline() && !isAnonymousColumnSpanBlock()) {
+        && !newChild->isFloatingOrOutOfFlowPositioned() && !newChild->isInline() && !isAnonymousColumnSpanBlock()) {
         columnsBlockAncestor = containingColumnsBlock(false);
         if (columnsBlockAncestor) {
             // Make sure that none of the parent ancestors have a continuation.
@@ -885,7 +885,7 @@ void RenderBlock::addChildIgnoringAnonymousColumnBlocks(RenderObject* newChild,
     // A block has to either have all of its children inline, or all of its children as blocks.
     // So, if our children are currently inline and a block child has to be inserted, we move all our
     // inline children into anonymous block boxes.
-    if (childrenInline() && !newChild->isInline() && !newChild->isFloatingOrPositioned()) {
+    if (childrenInline() && !newChild->isInline() && !newChild->isFloatingOrOutOfFlowPositioned()) {
         // This is a block with inline content. Wrap the inline content in anonymous blocks.
         makeChildrenNonInline(beforeChild);
         madeBoxesNonInline = true;
@@ -895,7 +895,7 @@ void RenderBlock::addChildIgnoringAnonymousColumnBlocks(RenderObject* newChild,
             ASSERT(beforeChild->isAnonymousBlock());
             ASSERT(beforeChild->parent() == this);
         }
-    } else if (!childrenInline() && (newChild->isFloatingOrPositioned() || newChild->isInline())) {
+    } else if (!childrenInline() && (newChild->isFloatingOrOutOfFlowPositioned() || newChild->isInline())) {
         // If we're inserting an inline child but all of our children are blocks, then we have to make sure
         // it is put into an anomyous block box. We try to use an existing anonymous box if possible, otherwise
         // a new one is created and inserted into our list of children in the appropriate position.
@@ -961,7 +961,7 @@ static void getInlineRun(RenderObject* start, RenderObject* boundary,
     RenderObject * curr = start;
     bool sawInline;
     do {
-        while (curr && !(curr->isInline() || curr->isFloatingOrPositioned()))
+        while (curr && !(curr->isInline() || curr->isFloatingOrOutOfFlowPositioned()))
             curr = curr->nextSibling();
         
         inlineRunStart = inlineRunEnd = curr;
@@ -972,7 +972,7 @@ static void getInlineRun(RenderObject* start, RenderObject* boundary,
         sawInline = curr->isInline();
         
         curr = curr->nextSibling();
-        while (curr && (curr->isInline() || curr->isFloatingOrPositioned()) && (curr != boundary)) {
+        while (curr && (curr->isInline() || curr->isFloatingOrOutOfFlowPositioned()) && (curr != boundary)) {
             inlineRunEnd = curr;
             if (curr->isInline())
                 sawInline = true;
@@ -1283,7 +1283,7 @@ bool RenderBlock::isSelfCollapsingBlock() const
         // Whether or not we collapse is dependent on whether all our normal flow children
         // are also self-collapsing.
         for (RenderBox* child = firstChildBox(); child; child = child->nextSiblingBox()) {
-            if (child->isFloatingOrPositioned())
+            if (child->isFloatingOrOutOfFlowPositioned())
                 continue;
             if (!child->isSelfCollapsingBlock())
                 return false;
@@ -1507,7 +1507,7 @@ void RenderBlock::layoutBlock(bool relayoutChildren, LayoutUnit pageLogicalHeigh
         if (oldHeight > newHeight && maxFloatLogicalBottom > newHeight && !childrenInline()) {
             // One of our children's floats may have become an overhanging float for us. We need to look for it.
             for (RenderObject* child = firstChild(); child; child = child->nextSibling()) {
-                if (child->isBlockFlow() && !child->isFloatingOrPositioned()) {
+                if (child->isBlockFlow() && !child->isFloatingOrOutOfFlowPositioned()) {
                     RenderBlock* block = toRenderBlock(child);
                     if (block->lowestFloatLogicalBottom() + block->logicalTop() > newHeight)
                         addOverhangingFloats(block, false);
@@ -1638,7 +1638,7 @@ void RenderBlock::computeOverflow(LayoutUnit oldClientAfterEdge, bool recomputeF
 void RenderBlock::addOverflowFromBlockChildren()
 {
     for (RenderBox* child = firstChildBox(); child; child = child->nextSiblingBox()) {
-        if (!child->isFloatingOrPositioned())
+        if (!child->isFloatingOrOutOfFlowPositioned())
             addOverflowFromChild(child);
     }
 }
@@ -1690,7 +1690,7 @@ void RenderBlock::addVisualOverflowFromTheme()
 
 bool RenderBlock::expandsToEncloseOverhangingFloats() const
 {
-    return isInlineBlockOrInlineTable() || isFloatingOrPositioned() || hasOverflowClip() || (parent() && parent()->isDeprecatedFlexibleBox())
+    return isInlineBlockOrInlineTable() || isFloatingOrOutOfFlowPositioned() || hasOverflowClip() || (parent() && parent()->isDeprecatedFlexibleBox())
            || hasColumns() || isTableCell() || isTableCaption() || isFieldset() || isWritingModeRoot() || isRoot();
 }
 
@@ -1756,7 +1756,7 @@ bool RenderBlock::handleSpecialChild(RenderBox* child, const MarginInfo& marginI
 
 bool RenderBlock::handlePositionedChild(RenderBox* child, const MarginInfo& marginInfo)
 {
-    if (child->isPositioned()) {
+    if (child->isOutOfFlowPositioned()) {
         child->containingBlock()->insertPositionedObject(child);
         adjustPositionedBlock(child, marginInfo);
         return true;
@@ -1869,7 +1869,7 @@ void RenderBlock::moveRunInUnderSiblingBlockIfNeeded(RenderObject* runIn)
     if (curr->isRunIn() || (curr->firstChild() && curr->firstChild()->isRunIn()))
         return;
 
-    if (curr->isAnonymous() || curr->isFloatingOrPositioned())
+    if (curr->isAnonymous() || curr->isFloatingOrOutOfFlowPositioned())
         return;
 
     RenderBoxModelObject* oldRunIn = toRenderBoxModelObject(runIn);
@@ -2031,7 +2031,7 @@ LayoutUnit RenderBlock::collapseMargins(RenderBox* child, MarginInfo& marginInfo
     // overhang from the previous sibling are added to our parent. If the child's previous sibling itself is a float the child will avoid
     // or clear it anyway, so don't worry about any floating children it may contain.
     RenderObject* prev = child->previousSibling();
-    if (prev && prev->isBlockFlow() && !prev->isFloatingOrPositioned()) {
+    if (prev && prev->isBlockFlow() && !prev->isFloatingOrOutOfFlowPositioned()) {
         RenderBlock* block = toRenderBlock(prev);
         if (block->containsFloats() && block->lowestFloatLogicalBottom() > logicalTop) 
             addOverhangingFloats(block, false);
@@ -2056,7 +2056,7 @@ LayoutUnit RenderBlock::clearFloatsIfNeeded(RenderBox* child, MarginInfo& margin
         // self-collapsing block's bottom margin.
         bool atBottomOfBlock = true;
         for (RenderBox* curr = child->nextSiblingBox(); curr && atBottomOfBlock; curr = curr->nextSiblingBox()) {
-            if (!curr->isFloatingOrPositioned())
+            if (!curr->isFloatingOrOutOfFlowPositioned())
                 atBottomOfBlock = false;
         }
         
@@ -2451,7 +2451,7 @@ void RenderBlock::simplifiedNormalFlowLayout()
         ListHashSet<RootInlineBox*> lineBoxes;
         for (InlineWalker walker(this); !walker.atEnd(); walker.advance()) {
             RenderObject* o = walker.current();
-            if (!o->isPositioned() && (o->isReplaced() || o->isFloating())) {
+            if (!o->isOutOfFlowPositioned() && (o->isReplaced() || o->isFloating())) {
                 o->layoutIfNeeded();
                 if (toRenderBox(o)->inlineBoxWrapper()) {
                     RootInlineBox* box = toRenderBox(o)->inlineBoxWrapper()->root();
@@ -2469,7 +2469,7 @@ void RenderBlock::simplifiedNormalFlowLayout()
         }
     } else {
         for (RenderBox* box = firstChildBox(); box; box = box->nextSiblingBox()) {
-            if (!box->isPositioned())
+            if (!box->isOutOfFlowPositioned())
                 box->layoutIfNeeded();
         }
     }
@@ -3133,9 +3133,9 @@ bool RenderBlock::isSelectionRoot() const
     if (isTable())
         return false;
         
-    if (isBody() || isRoot() || hasOverflowClip() || isRelPositioned() ||
-        isFloatingOrPositioned() || isTableCell() || isInlineBlockOrInlineTable() || hasTransform() ||
-        hasReflection() || hasMask() || isWritingModeRoot())
+    if (isBody() || isRoot() || hasOverflowClip() || isRelPositioned()
+        || isFloatingOrOutOfFlowPositioned() || isTableCell() || isInlineBlockOrInlineTable() || hasTransform()
+        || hasReflection() || hasMask() || isWritingModeRoot())
         return true;
     
     if (view() && view()->selectionStart()) {
@@ -3352,7 +3352,7 @@ GapRects RenderBlock::blockSelectionGaps(RenderBlock* rootBlock, const LayoutPoi
         if (childState == SelectionBoth || childState == SelectionEnd)
             sawSelectionEnd = true;
 
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue; // We must be a normal flow object in order to even be considered.
 
         if (curr->isRelPositioned() && curr->hasLayer()) {
@@ -4179,7 +4179,7 @@ void RenderBlock::clearFloats()
     }
 
     // Inline blocks are covered by the isReplaced() check in the avoidFloats method.
-    if (avoidsFloats() || isRoot() || isRenderView() || isFloatingOrPositioned() || isTableCell()) {
+    if (avoidsFloats() || isRoot() || isRenderView() || isFloatingOrOutOfFlowPositioned() || isTableCell()) {
         if (m_floatingObjects) {
             deleteAllValues(m_floatingObjects->set());
             m_floatingObjects->clear();
@@ -4217,7 +4217,7 @@ void RenderBlock::clearFloats()
     RenderBlock* parentBlock = toRenderBlock(parent());
     bool parentHasFloats = false;
     RenderObject* prev = previousSibling();
-    while (prev && (prev->isFloatingOrPositioned() || !prev->isBox() || !prev->isRenderBlock() || toRenderBlock(prev)->avoidsFloats())) {
+    while (prev && (prev->isFloatingOrOutOfFlowPositioned() || !prev->isBox() || !prev->isRenderBlock() || toRenderBlock(prev)->avoidsFloats())) {
         if (prev->isFloating())
             parentHasFloats = true;
         prev = prev->previousSibling();
@@ -4451,7 +4451,7 @@ void RenderBlock::markAllDescendantsWithFloatsForLayout(RenderBox* floatToRemove
     // Iterate over our children and mark them as needed.
     if (!childrenInline()) {
         for (RenderObject* child = firstChild(); child; child = child->nextSibling()) {
-            if ((!floatToRemove && child->isFloatingOrPositioned()) || !child->isRenderBlock())
+            if ((!floatToRemove && child->isFloatingOrOutOfFlowPositioned()) || !child->isRenderBlock())
                 continue;
             RenderBlock* childBlock = toRenderBlock(child);
             if ((floatToRemove ? childBlock->containsFloat(floatToRemove) : childBlock->containsFloats()) || childBlock->shrinkToAvoidFloats())
@@ -4469,7 +4469,7 @@ void RenderBlock::markSiblingsWithFloatsForLayout(RenderBox* floatToRemove)
     FloatingObjectSetIterator end = floatingObjectSet.end();
 
     for (RenderObject* next = nextSibling(); next; next = next->nextSibling()) {
-        if (!next->isRenderBlock() || next->isFloatingOrPositioned() || toRenderBlock(next)->avoidsFloats())
+        if (!next->isRenderBlock() || next->isFloatingOrOutOfFlowPositioned() || toRenderBlock(next)->avoidsFloats())
             continue;
 
         RenderBlock* nextBlock = toRenderBlock(next);
@@ -4884,7 +4884,7 @@ VisiblePosition RenderBlock::positionForPointWithInlineChildren(const LayoutPoin
 
 static inline bool isChildHitTestCandidate(RenderBox* box)
 {
-    return box->height() && box->style()->visibility() == VISIBLE && !box->isFloatingOrPositioned();
+    return box->height() && box->style()->visibility() == VISIBLE && !box->isFloatingOrOutOfFlowPositioned();
 }
 
 VisiblePosition RenderBlock::positionForPoint(const LayoutPoint& point)
@@ -5417,7 +5417,7 @@ RenderObject* InlineMinMaxIterator::next()
     while (current || current == parent) {
         if (!oldEndOfInline &&
             (current == parent ||
-             (!current->isFloating() && !current->isReplaced() && !current->isPositioned())))
+             (!current->isFloating() && !current->isReplaced() && !current->isOutOfFlowPositioned())))
             result = current->firstChild();
         if (!result) {
             // We hit the end of our inline. (It was empty, e.g., <span></span>.)
@@ -5442,7 +5442,7 @@ RenderObject* InlineMinMaxIterator::next()
         if (!result)
             break;
 
-        if (!result->isPositioned() && (result->isText() || result->isFloating() || result->isReplaced() || result->isRenderInline()))
+        if (!result->isOutOfFlowPositioned() && (result->isText() || result->isFloating() || result->isReplaced() || result->isRenderInline()))
              break;
         
         current = result;
@@ -5768,7 +5768,7 @@ void RenderBlock::computeBlockPreferredLogicalWidths()
     LayoutUnit floatLeftWidth = 0, floatRightWidth = 0;
     while (child) {
         // Positioned children don't affect the min/max width
-        if (child->isPositioned()) {
+        if (child->isOutOfFlowPositioned()) {
             child = child->nextSibling();
             continue;
         }
@@ -5942,7 +5942,7 @@ LayoutUnit RenderBlock::firstLineBoxBaseline() const
     }
     else {
         for (RenderBox* curr = firstChildBox(); curr; curr = curr->nextSiblingBox()) {
-            if (!curr->isFloatingOrPositioned()) {
+            if (!curr->isFloatingOrOutOfFlowPositioned()) {
                 LayoutUnit result = curr->firstLineBoxBaseline();
                 if (result != -1)
                     return curr->logicalTop() + result; // Translate to our coordinate space.
@@ -5973,7 +5973,7 @@ LayoutUnit RenderBlock::lastLineBoxBaseline() const
     } else {
         bool haveNormalFlowChild = false;
         for (RenderBox* curr = lastChildBox(); curr; curr = curr->previousSiblingBox()) {
-            if (!curr->isFloatingOrPositioned()) {
+            if (!curr->isFloatingOrOutOfFlowPositioned()) {
                 haveNormalFlowChild = true;
                 LayoutUnit result = curr->lastLineBoxBaseline();
                 if (result != -1)
@@ -6208,7 +6208,7 @@ void RenderBlock::updateFirstLetter()
             break;
         if (currChild->isListMarker())
             currChild = currChild->nextSibling();
-        else if (currChild->isFloatingOrPositioned()) {
+        else if (currChild->isFloatingOrOutOfFlowPositioned()) {
             if (currChild->style()->styleType() == FIRST_LETTER) {
                 currChild = currChild->firstChild();
                 break;
@@ -6248,9 +6248,9 @@ void RenderBlock::updateFirstLetter()
 // (crawling into blocks).
 static bool shouldCheckLines(RenderObject* obj)
 {
-    return !obj->isFloatingOrPositioned() && !obj->isRunIn() &&
-            obj->isBlockFlow() && obj->style()->height().isAuto() &&
-            (!obj->isDeprecatedFlexibleBox() || obj->style()->boxOrient() == VERTICAL);
+    return !obj->isFloatingOrOutOfFlowPositioned() && !obj->isRunIn()
+            && obj->isBlockFlow() && obj->style()->height().isAuto()
+            && (!obj->isDeprecatedFlexibleBox() || obj->style()->boxOrient() == VERTICAL);
 }
 
 static RootInlineBox* getLineAtIndex(RenderBlock* block, int i, int& count)
@@ -6291,8 +6291,7 @@ static int getHeightForLineCount(RenderBlock* block, int l, bool includeBottom,
                     int result = getHeightForLineCount(toRenderBlock(obj), l, false, count);
                     if (result != -1)
                         return result + obj->y() + (includeBottom ? (block->borderBottom() + block->paddingBottom()) : ZERO_LAYOUT_UNIT);
-                }
-                else if (!obj->isFloatingOrPositioned() && !obj->isRunIn())
+                } else if (!obj->isFloatingOrOutOfFlowPositioned() && !obj->isRunIn())
                     normalFlowChildWithoutLines = obj;
             }
             if (normalFlowChildWithoutLines && l == 0)
@@ -6345,7 +6344,7 @@ void RenderBlock::adjustForBorderFit(LayoutUnit x, LayoutUnit& left, LayoutUnit&
         }
         else {
             for (RenderBox* obj = firstChildBox(); obj; obj = obj->nextSiblingBox()) {
-                if (!obj->isFloatingOrPositioned()) {
+                if (!obj->isFloatingOrOutOfFlowPositioned()) {
                     if (obj->isBlockFlow() && !obj->hasOverflowClip())
                         toRenderBlock(obj)->adjustForBorderFit(x + obj->x(), left, right);
                     else if (obj->style()->visibility() == VISIBLE) {
@@ -6669,7 +6668,7 @@ static bool inNormalFlow(RenderBox* child)
     while (curr && curr != renderView) {
         if (curr->hasColumns() || curr->isRenderFlowThread())
             return true;
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             return false;
         curr = curr->containingBlock();
     }
@@ -6848,7 +6847,7 @@ void RenderBlock::adjustLinePositionForPagination(RootInlineBox* lineBox, Layout
         }
         LayoutUnit totalLogicalHeight = lineHeight + max(ZERO_LAYOUT_UNIT, logicalOffset);
         LayoutUnit pageLogicalHeightAtNewOffset = hasUniformPageLogicalHeight ? pageLogicalHeight : pageLogicalHeightForOffset(logicalOffset + remainingLogicalHeight);
-        if (lineBox == firstRootBox() && totalLogicalHeight < pageLogicalHeightAtNewOffset && !isPositioned() && !isTableCell())
+        if (lineBox == firstRootBox() && totalLogicalHeight < pageLogicalHeightAtNewOffset && !isOutOfFlowPositioned() && !isTableCell())
             setPaginationStrut(remainingLogicalHeight + max(ZERO_LAYOUT_UNIT, logicalOffset));
         else {
             delta += remainingLogicalHeight;
@@ -6905,7 +6904,7 @@ LayoutUnit RenderBlock::adjustBlockChildForPagination(LayoutUnit logicalTopAfter
     if (paginationStrut) {
         // We are willing to propagate out to our parent block as long as we were at the top of the block prior
         // to collapsing our margins, and as long as we didn't clear or move as a result of other pagination.
-        if (atBeforeSideOfBlock && oldTop == result && !isPositioned() && !isTableCell()) {
+        if (atBeforeSideOfBlock && oldTop == result && !isOutOfFlowPositioned() && !isTableCell()) {
             // FIXME: Should really check if we're exceeding the page height before propagating the strut, but we don't
             // have all the information to do so (the strut only has the remaining amount to push). Gecko gets this wrong too
             // and pushes to the next page anyway, so not too concerned about it.
@@ -7103,7 +7102,7 @@ const char* RenderBlock::renderName() const
     
     if (isFloating())
         return "RenderBlock (floating)";
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         return "RenderBlock (positioned)";
     if (isAnonymousColumnsBlock())
         return "RenderBlock (anonymous multi-column)";
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBlock.h`

```diff
@@ -247,7 +247,7 @@ class RenderBlock : public RenderBox {
 
     static bool shouldSkipCreatingRunsForObject(RenderObject* obj)
     {
-        return obj->isFloating() || (obj->isPositioned() && !obj->style()->isOriginalDisplayInlineType() && !obj->container()->isRenderInline());
+        return obj->isFloating() || (obj->isOutOfFlowPositioned() && !obj->style()->isOriginalDisplayInlineType() && !obj->container()->isRenderInline());
     }
     
     static void appendRunsForObject(BidiRunList<BidiRun>&, int start, int end, RenderObject*, InlineBidiResolver&);
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBlockLineLayout.cpp`

```diff
@@ -617,7 +617,7 @@ void RenderBlock::setMarginsForRubyRun(BidiRun* run, RenderRubyRun* renderer, Re
     int endOverhang;
     RenderObject* nextObject = 0;
     for (BidiRun* runWithNextObject = run->next(); runWithNextObject; runWithNextObject = runWithNextObject->next()) {
-        if (!runWithNextObject->m_object->isPositioned() && !runWithNextObject->m_box->isLineBreak()) {
+        if (!runWithNextObject->m_object->isOutOfFlowPositioned() && !runWithNextObject->m_box->isLineBreak()) {
             nextObject = runWithNextObject->m_object;
             break;
         }
@@ -762,7 +762,7 @@ void RenderBlock::computeInlineDirectionPositionsForLine(RootInlineBox* lineBox,
     RenderObject* previousObject = 0;
 
     for (BidiRun* r = firstRun; r; r = r->next()) {
-        if (!r->m_box || r->m_object->isPositioned() || r->m_box->isLineBreak())
+        if (!r->m_box || r->m_object->isOutOfFlowPositioned() || r->m_box->isLineBreak())
             continue; // Positioned objects are only participating to figure out their
                       // correct static x position.  They have no effect on the width.
                       // Similarly, line break boxes have no effect on the width.
@@ -826,7 +826,7 @@ void RenderBlock::computeBlockDirectionPositionsForLine(RootInlineBox* lineBox,
 
         // Align positioned boxes with the top of the line box.  This is
         // a reasonable approximation of an appropriate y position.
-        if (r->m_object->isPositioned())
+        if (r->m_object->isOutOfFlowPositioned())
             r->m_box->setLogicalTop(logicalHeight());
 
         // Position is used to properly position both replaced elements and
@@ -1478,7 +1478,7 @@ void RenderBlock::layoutInlineChildren(bool relayoutChildren, LayoutUnit& repain
             if (!hasInlineChild && o->isInline())
                 hasInlineChild = true;
 
-            if (o->isReplaced() || o->isFloating() || o->isPositioned()) {
+            if (o->isReplaced() || o->isFloating() || o->isOutOfFlowPositioned()) {
                 RenderBox* box = toRenderBox(o);
 
                 if (relayoutChildren || box->hasRelativeDimensions())
@@ -1488,7 +1488,7 @@ void RenderBlock::layoutInlineChildren(bool relayoutChildren, LayoutUnit& repain
                 if (relayoutChildren && box->needsPreferredWidthsRecalculation())
                     o->setPreferredLogicalWidthsDirty(true, MarkOnlyThis);
 
-                if (o->isPositioned())
+                if (o->isOutOfFlowPositioned())
                     o->containingBlock()->insertPositionedObject(box);
                 else if (o->isFloating())
                     layoutState.floats().append(FloatWithRect(box));
@@ -1849,7 +1849,7 @@ static bool alwaysRequiresLineBox(RenderInline* flow)
 
 static bool requiresLineBox(const InlineIterator& it, const LineInfo& lineInfo = LineInfo(), WhitespacePosition whitespacePosition = LeadingWhitespace)
 {
-    if (it.m_obj->isFloatingOrPositioned())
+    if (it.m_obj->isFloatingOrOutOfFlowPositioned())
         return false;
 
     if (it.m_obj->isRenderInline() && !alwaysRequiresLineBox(toRenderInline(it.m_obj)) && !requiresLineBoxForContent(toRenderInline(it.m_obj), lineInfo))
@@ -1885,7 +1885,7 @@ void RenderBlock::LineBreaker::skipTrailingWhitespace(InlineIterator& iterator,
 {
     while (!iterator.atEnd() && !requiresLineBox(iterator, lineInfo, TrailingWhitespace)) {
         RenderObject* object = iterator.m_obj;
-        if (object->isPositioned())
+        if (object->isOutOfFlowPositioned())
             setStaticPositions(m_block, toRenderBox(object));
         else if (object->isFloating())
             m_block->insertFloatingObject(toRenderBox(object));
@@ -1898,7 +1898,7 @@ void RenderBlock::LineBreaker::skipLeadingWhitespace(InlineBidiResolver& resolve
 {
     while (!resolver.position().atEnd() && !requiresLineBox(resolver.position(), lineInfo, LeadingWhitespace)) {
         RenderObject* object = resolver.position().m_obj;
-        if (object->isPositioned()) {
+        if (object->isOutOfFlowPositioned()) {
             setStaticPositions(m_block, toRenderBox(object));
             if (object->style()->isOriginalDisplayInlineType()) {
                 resolver.runs().addRun(createRun(0, 1, object, resolver));
@@ -2192,7 +2192,7 @@ InlineIterator RenderBlock::LineBreaker::nextLineBreak(InlineBidiResolver& resol
             goto end;
         }
 
-        if (current.m_obj->isPositioned()) {
+        if (current.m_obj->isOutOfFlowPositioned()) {
             // If our original display wasn't an inline type, then we can
             // go ahead and determine our static inline position now.
             RenderBox* box = toRenderBox(current.m_obj);
@@ -2599,7 +2599,7 @@ InlineIterator RenderBlock::LineBreaker::nextLineBreak(InlineBidiResolver& resol
                 goto end;
         }
 
-        if (!current.m_obj->isFloatingOrPositioned()) {
+        if (!current.m_obj->isFloatingOrOutOfFlowPositioned()) {
             last = current.m_obj;
             if (last->isReplaced() && autoWrap && (!last->isImage() || allowImagesToBreak) && (!last->isListMarker() || toRenderListMarker(last)->isInside())) {
                 width.commit();
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBox.cpp`

```diff
@@ -150,7 +150,7 @@ void RenderBox::willBeDestroyed()
 
 void RenderBox::removeFloatingOrPositionedChildFromBlockLists()
 {
-    ASSERT(isFloatingOrPositioned());
+    ASSERT(isFloatingOrOutOfFlowPositioned());
 
     if (documentBeingDestroyed())
         return;
@@ -175,7 +175,7 @@ void RenderBox::removeFloatingOrPositionedChildFromBlockLists()
         }
     }
 
-    if (isPositioned()) {
+    if (isOutOfFlowPositioned()) {
         for (RenderObject* curr = parent(); curr; curr = curr->parent()) {
             if (curr->isRenderBlock())
                 toRenderBlock(curr)->removePositionedObject(this);
@@ -201,9 +201,9 @@ void RenderBox::styleWillChange(StyleDifference diff, const RenderStyle* newStyl
             markContainingBlocksForLayout();
             if (oldStyle->position() == StaticPosition)
                 repaint();
-            else if (newStyle->isPositioned())
+            else if (newStyle->isOutOfFlowPositioned())
                 parent()->setChildNeedsLayout(true);
-            if (isFloating() && !isPositioned() && newStyle->isPositioned())
+            if (isFloating() && !isOutOfFlowPositioned() && newStyle->isOutOfFlowPositioned())
                 removeFloatingOrPositionedChildFromBlockLists();
         }
     } else if (newStyle && isBody())
@@ -239,7 +239,7 @@ void RenderBox::styleDidChange(StyleDifference diff, const RenderStyle* oldStyle
         // Normally we can do optimized positioning layout for absolute/fixed positioned objects. There is one special case, however, which is
         // when the positioned object's margin-before is changed. In this case the parent has to get a layout in order to run margin collapsing
         // to determine the new static position.
-        if (isPositioned() && newStyle->hasStaticBlockPosition(isHorizontalWritingMode()) && oldStyle->marginBefore() != newStyle->marginBefore()
+        if (isOutOfFlowPositioned() && newStyle->hasStaticBlockPosition(isHorizontalWritingMode()) && oldStyle->marginBefore() != newStyle->marginBefore()
             && parent() && !parent()->normalChildNeedsLayout())
             parent()->setChildNeedsLayout(true);
     }
@@ -305,8 +305,8 @@ void RenderBox::updateBoxModelInfoFromStyle()
     if (isRootObject || isViewObject)
         setHasBoxDecorations(true);
 
-    setPositioned(styleToUse->isPositioned());
-    setFloating(!isPositioned() && styleToUse->isFloating());
+    setPositioned(styleToUse->isOutOfFlowPositioned());
+    setFloating(!isOutOfFlowPositioned() && styleToUse->isFloating());
 
     // We also handle <body> and <html>, whose overflow applies to the viewport.
     if (styleToUse->overflowX() != OVISIBLE && !isRootObject && (isRenderBlock() || isTableRow() || isTableSection())) {
@@ -1388,7 +1388,7 @@ LayoutSize RenderBox::offsetFromContainer(RenderObject* o, const LayoutPoint& po
         offset += relativePositionOffset();
 
     if (!isInline() || isReplaced()) {
-        if (!style()->isPositioned() && o->hasColumns()) {
+        if (!style()->isOutOfFlowPositioned() && o->hasColumns()) {
             RenderBlock* block = toRenderBlock(o);
             LayoutRect columnRect(frameRect());
             block->adjustStartEdgeForWritingModeIncludingColumns(columnRect);
@@ -1431,7 +1431,7 @@ void RenderBox::dirtyLineBoxes(bool fullLayout)
 
 void RenderBox::positionLineBox(InlineBox* box)
 {
-    if (isPositioned()) {
+    if (isOutOfFlowPositioned()) {
         // Cache the x position only if we were an INLINE type originally.
         bool wasInline = style()->isOriginalDisplayInlineType();
         if (wasInline) {
@@ -1546,7 +1546,7 @@ void RenderBox::computeRectForRepaint(RenderBoxModelObject* repaintContainer, La
     if (!o)
         return;
 
-    if (isWritingModeRoot() && !isPositioned())
+    if (isWritingModeRoot() && !isOutOfFlowPositioned())
         flipForWritingMode(rect);
 
     LayoutPoint topLeft = rect.location();
@@ -1637,7 +1637,7 @@ void RenderBox::computeLogicalWidth()
 
 void RenderBox::computeLogicalWidthInRegion(RenderRegion* region, LayoutUnit offsetFromLogicalTopOfFirstPage)
 {
-    if (isPositioned()) {
+    if (isOutOfFlowPositioned()) {
         // FIXME: This calculation is not patched for block-flow yet.
         // [url removida]
         computePositionedLogicalWidth(region, offsetFromLogicalTopOfFirstPage);
@@ -1917,10 +1917,10 @@ RenderBoxRegionInfo* RenderBox::renderBoxRegionInfo(RenderRegion* region, Layout
     LayoutUnit logicalWidthInRegion = logicalWidth();
     LayoutUnit logicalLeftInRegion = logicalLeft();
     LayoutUnit widthDelta = logicalWidthInRegion - oldLogicalWidth;
-    LayoutUnit logicalLeftDelta = isPositioned() ? logicalLeftInRegion - oldLogicalLeft : startMarginDelta;
+    LayoutUnit logicalLeftDelta = isOutOfFlowPositioned() ? logicalLeftInRegion - oldLogicalLeft : startMarginDelta;
     LayoutUnit logicalRightInRegion = containingBlockLogicalWidthInRegion - (logicalLeftInRegion + logicalWidthInRegion);
     LayoutUnit oldLogicalRight = containingBlockLogicalWidth - (oldLogicalLeft + oldLogicalWidth);
-    LayoutUnit logicalRightDelta = isPositioned() ? logicalRightInRegion - oldLogicalRight : startMarginDelta;
+    LayoutUnit logicalRightDelta = isOutOfFlowPositioned() ? logicalRightInRegion - oldLogicalRight : startMarginDelta;
 
     // Set our values back.
     mutableBox->setLogicalWidth(oldLogicalWidth);
@@ -1930,7 +1930,7 @@ RenderBoxRegionInfo* RenderBox::renderBoxRegionInfo(RenderRegion* region, Layout
 
     LayoutUnit logicalLeftOffset = 0;
     
-    if (!isPositioned() && avoidsFloats() && cb->containsFloats()) {
+    if (!isOutOfFlowPositioned() && avoidsFloats() && cb->containsFloats()) {
         LayoutUnit startPositionDelta = cb->computeStartPositionDeltaForChildAvoidingFloats(this, marginStartInRegion, region, offsetFromLogicalTopOfFirstPage);
         if (cb->style()->isLeftToRightDirection())
             logicalLeftDelta += startPositionDelta;
@@ -1961,7 +1961,7 @@ void RenderBox::computeLogicalHeight()
         return;
 
     Length h;
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         computePositionedLogicalHeight();
     else {
         RenderBlock* cb = containingBlock();
@@ -2093,7 +2093,7 @@ LayoutUnit RenderBox::computePercentageLogicalHeight(const Length& height)
     // only at explicit containers.
     bool skippedAutoHeightContainingBlock = false;
     RenderBlock* cb = containingBlock();
-    while (!cb->isRenderView() && !cb->isBody() && !cb->isTableCell() && !cb->isPositioned() && cb->style()->logicalHeight().isAuto()) {
+    while (!cb->isRenderView() && !cb->isBody() && !cb->isTableCell() && !cb->isOutOfFlowPositioned() && cb->style()->logicalHeight().isAuto()) {
         if (!document()->inQuirksMode() && !cb->isAnonymousBlock())
             break;
         skippedAutoHeightContainingBlock = true;
@@ -2107,7 +2107,7 @@ LayoutUnit RenderBox::computePercentageLogicalHeight(const Length& height)
     // explicitly specified that can be used for any percentage computations.
     // FIXME: We can't just check top/bottom here.
     // [url removida]
-    bool isPositionedWithSpecifiedHeight = cb->isPositioned() && (!cbstyle->logicalHeight().isAuto() || (!cbstyle->top().isAuto() && !cbstyle->bottom().isAuto()));
+    bool isOutOfFlowPositionedWithSpecifiedHeight = cb->isOutOfFlowPositioned() && (!cbstyle->logicalHeight().isAuto() || (!cbstyle->top().isAuto() && !cbstyle->bottom().isAuto()));
 
     bool includeBorderPadding = isTable();
 
@@ -2137,19 +2137,19 @@ LayoutUnit RenderBox::computePercentageLogicalHeight(const Length& height)
     // height.
     else if (cbstyle->logicalHeight().isFixed())
         result = cb->computeContentBoxLogicalHeight(cbstyle->logicalHeight().value());
-    else if (cbstyle->logicalHeight().isPercent() && !isPositionedWithSpecifiedHeight) {
+    else if (cbstyle->logicalHeight().isPercent() && !isOutOfFlowPositionedWithSpecifiedHeight) {
         // We need to recur and compute the percentage height for our containing block.
         result = cb->computePercentageLogicalHeight(cbstyle->logicalHeight());
         if (result != -1)
             result = cb->computeContentBoxLogicalHeight(result);
-    } else if (cb->isRenderView() || (cb->isBody() && document()->inQuirksMode()) || isPositionedWithSpecifiedHeight) {
+    } else if (cb->isRenderView() || (cb->isBody() && document()->inQuirksMode()) || isOutOfFlowPositionedWithSpecifiedHeight) {
         // Don't allow this to affect the block' height() member variable, since this
         // can get called while the block is still laying out its kids.
         LayoutUnit oldHeight = cb->logicalHeight();
         cb->computeLogicalHeight();
         result = cb->contentLogicalHeight();
         cb->setLogicalHeight(oldHeight);
-    } else if (cb->isRoot() && isPositioned())
+    } else if (cb->isRoot() && isOutOfFlowPositioned())
         // Match the positioned objects behavior, which is that positioned objects will fill their viewport
         // always.  Note we could only hit this case by recurring into computePercentageLogicalHeight on a positioned containing block.
         result = cb->computeContentBoxLogicalHeight(cb->availableLogicalHeight());
@@ -2193,7 +2193,7 @@ LayoutUnit RenderBox::computeReplacedLogicalWidthUsing(Length logicalWidth) cons
             // FIXME: containingBlockLogicalWidthForContent() is wrong if the replaced element's block-flow is perpendicular to the
             // containing block's block-flow.
             // [url removida]
-            const LayoutUnit cw = isPositioned() ? containingBlockLogicalWidthForPositioned(toRenderBoxModelObject(container())) : containingBlockLogicalWidthForContent();
+            const LayoutUnit cw = isOutOfFlowPositioned() ? containingBlockLogicalWidthForPositioned(toRenderBoxModelObject(container())) : containingBlockLogicalWidthForContent();
             if (cw > 0)
                 return computeContentBoxLogicalWidth(minimumValueForLength(logicalWidth, cw));
         }
@@ -2223,15 +2223,15 @@ LayoutUnit RenderBox::computeReplacedLogicalHeightUsing(Length logicalHeight) co
         case Percent:
         case Calculated:
         {
-            RenderObject* cb = isPositioned() ? container() : containingBlock();
+            RenderObject* cb = isOutOfFlowPositioned() ? container() : containingBlock();
             while (cb->isAnonymous()) {
                 cb = cb->containingBlock();
                 toRenderBlock(cb)->addPercentHeightDescendant(const_cast<RenderBox*>(this));
             }
 
             // FIXME: This calculation is not patched for block-flow yet.
             // [url removida]
-            if (cb->isPositioned() && cb->style()->height().isAuto() && !(cb->style()->top().isAuto() || cb->style()->bottom().isAuto())) {
+            if (cb->isOutOfFlowPositioned() && cb->style()->height().isAuto() && !(cb->style()->top().isAuto() || cb->style()->bottom().isAuto())) {
                 ASSERT(cb->isRenderBlock());
                 RenderBlock* block = toRenderBlock(cb);
                 LayoutUnit oldHeight = block->height();
@@ -2245,7 +2245,7 @@ LayoutUnit RenderBox::computeReplacedLogicalHeightUsing(Length logicalHeight) co
             // containing block's block-flow.
             // [url removida]
             LayoutUnit availableHeight;
-            if (isPositioned())
+            if (isOutOfFlowPositioned())
                 availableHeight = containingBlockLogicalHeightForPositioned(toRenderBoxModelObject(cb));
             else {
                 availableHeight =  toRenderBox(cb)->availableLogicalHeight();
@@ -2300,7 +2300,7 @@ LayoutUnit RenderBox::availableLogicalHeightUsing(const Length& h) const
         // [url removida]
         // For absolutely positioned elements whose containing block is based on a block-level element,
         // the percentage is calculated with respect to the height of the padding box of that element
-        if (isPositioned())
+        if (isOutOfFlowPositioned())
             availableHeight = containingBlockLogicalHeightForPositioned(containingBlock());
         else
             availableHeight = containingBlock()->availableLogicalHeight();
@@ -2309,7 +2309,7 @@ LayoutUnit RenderBox::availableLogicalHeightUsing(const Length& h) const
 
     // FIXME: We can't just check top/bottom here.
     // [url removida]
-    if (isRenderBlock() && isPositioned() && style()->height().isAuto() && !(style()->top().isAuto() || style()->bottom().isAuto())) {
+    if (isRenderBlock() && isOutOfFlowPositioned() && style()->height().isAuto() && !(style()->top().isAuto() || style()->bottom().isAuto())) {
         RenderBlock* block = const_cast<RenderBlock*>(toRenderBlock(this));
         LayoutUnit oldHeight = block->logicalHeight();
         block->computeLogicalHeight();
@@ -3679,7 +3679,7 @@ static bool percentageLogicalHeightIsResolvable(const RenderBox* box)
     // block has an auto height. We still skip anonymous containing blocks in both modes, though, and look
     // only at explicit containers.
     const RenderBlock* cb = box->containingBlock();
-    while (!cb->isRenderView() && !cb->isBody() && !cb->isTableCell() && !cb->isPositioned() && cb->style()->logicalHeight().isAuto()) {
+    while (!cb->isRenderView() && !cb->isBody() && !cb->isTableCell() && !cb->isOutOfFlowPositioned() && cb->style()->logicalHeight().isAuto()) {
         if (!box->document()->inQuirksMode() && !cb->isAnonymousBlock())
             break;
         cb = cb->containingBlock();
@@ -3689,7 +3689,7 @@ static bool percentageLogicalHeightIsResolvable(const RenderBox* box)
     // explicitly specified that can be used for any percentage computations.
     // FIXME: We can't just check top/bottom here.
     // [url removida]
-    bool isPositionedWithSpecifiedHeight = cb->isPositioned() && (!cb->style()->logicalHeight().isAuto() || (!cb->style()->top().isAuto() && !cb->style()->bottom().isAuto()));
+    bool isOutOfFlowPositionedWithSpecifiedHeight = cb->isOutOfFlowPositioned() && (!cb->style()->logicalHeight().isAuto() || (!cb->style()->top().isAuto() && !cb->style()->bottom().isAuto()));
 
     // Table cells violate what the CSS spec says to do with heights.  Basically we
     // don't care if the cell specified a height or not.  We just always make ourselves
@@ -3701,11 +3701,11 @@ static bool percentageLogicalHeightIsResolvable(const RenderBox* box)
     // height.
     if (cb->style()->logicalHeight().isFixed())
         return true;
-    if (cb->style()->logicalHeight().isPercent() && !isPositionedWithSpecifiedHeight)
+    if (cb->style()->logicalHeight().isPercent() && !isOutOfFlowPositionedWithSpecifiedHeight)
         return percentageLogicalHeightIsResolvable(cb);
-    if (cb->isRenderView() || (cb->isBody() && box->document()->inQuirksMode()) || isPositionedWithSpecifiedHeight)
+    if (cb->isRenderView() || (cb->isBody() && box->document()->inQuirksMode()) || isOutOfFlowPositionedWithSpecifiedHeight)
         return true;
-    if (cb->isRoot() && box->isPositioned()) {
+    if (cb->isRoot() && box->isOutOfFlowPositioned()) {
         // Match the positioned objects behavior, which is that positioned objects will fill their viewport
         // always.  Note we could only hit this case by recurring into computePercentageLogicalHeight on a positioned containing block.
         return true;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBox.h`

```diff
@@ -42,7 +42,7 @@ class RenderBox : public RenderBoxModelObject {
     RenderBox(Node*);
     virtual ~RenderBox();
 
-    virtual bool requiresLayer() const OVERRIDE { return isRoot() || isPositioned() || isRelPositioned() || isTransparent() || hasOverflowClip() || hasTransform() || hasHiddenBackface() || hasMask() || hasReflection() || hasFilter() || style()->specifiesColumns(); }
+    virtual bool requiresLayer() const OVERRIDE { return isRoot() || isOutOfFlowPositioned() || isRelPositioned() || isTransparent() || hasOverflowClip() || hasTransform() || hasHiddenBackface() || hasMask() || hasReflection() || hasFilter() || style()->specifiesColumns(); }
 
     // Use this with caution! No type checking is done!
     RenderBox* firstChildBox() const;
@@ -326,7 +326,7 @@ class RenderBox : public RenderBoxModelObject {
 
     bool stretchesToViewport() const
     {
-        return document()->inQuirksMode() && style()->logicalHeight().isAuto() && !isFloatingOrPositioned() && (isRoot() || isBody()) && !document()->shouldDisplaySeamlesslyWithParent();
+        return document()->inQuirksMode() && style()->logicalHeight().isAuto() && !isFloatingOrOutOfFlowPositioned() && (isRoot() || isBody()) && !document()->shouldDisplaySeamlesslyWithParent();
     }
 
     virtual IntSize intrinsicSize() const { return IntSize(); }
@@ -427,7 +427,7 @@ class RenderBox : public RenderBoxModelObject {
 
     bool isWritingModeRoot() const { return !parent() || parent()->style()->writingMode() != style()->writingMode(); }
 
-    bool isDeprecatedFlexItem() const { return !isInline() && !isFloatingOrPositioned() && parent() && parent()->isDeprecatedFlexibleBox(); }
+    bool isDeprecatedFlexItem() const { return !isInline() && !isFloatingOrOutOfFlowPositioned() && parent() && parent()->isDeprecatedFlexibleBox(); }
     
     virtual LayoutUnit lineHeight(bool firstLine, LineDirectionMode, LinePositionMode = PositionOnContainingLine) const;
     virtual LayoutUnit baselinePosition(FontBaseline, bool firstLine, LineDirectionMode, LinePositionMode = PositionOnContainingLine) const;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBoxModelObject.cpp`

```diff
@@ -531,7 +531,7 @@ LayoutPoint RenderBoxModelObject::adjustedPositionRelativeToOffsetParent(const L
     if (const RenderBoxModelObject* offsetParent = this->offsetParent()) {
         if (offsetParent->isBox() && !offsetParent->isBody())
             referencePoint.move(-toRenderBox(offsetParent)->borderLeft(), -toRenderBox(offsetParent)->borderTop());
-        if (!isPositioned()) {
+        if (!isOutOfFlowPositioned()) {
             if (isRelPositioned())
                 referencePoint.move(relativePositionOffset());
             const RenderObject* curr = parent();
@@ -542,7 +542,7 @@ LayoutPoint RenderBoxModelObject::adjustedPositionRelativeToOffsetParent(const L
                 referencePoint.move(curr->parent()->offsetForColumns(referencePoint));
                 curr = curr->parent();
             }
-            if (offsetParent->isBox() && offsetParent->isBody() && !offsetParent->isRelPositioned() && !offsetParent->isPositioned())
+            if (offsetParent->isBox() && offsetParent->isBody() && !offsetParent->isRelPositioned() && !offsetParent->isOutOfFlowPositioned())
                 referencePoint.moveBy(toRenderBox(offsetParent)->topLeftLocation());
         }
     }
@@ -2740,7 +2740,7 @@ void RenderBoxModelObject::mapAbsoluteToLocalPoint(bool fixed, bool useTransform
 
     LayoutSize containerOffset = offsetFromContainer(o, LayoutPoint());
 
-    if (!style()->isPositioned() && o->hasColumns()) {
+    if (!style()->isOutOfFlowPositioned() && o->hasColumns()) {
         RenderBlock* block = static_cast<RenderBlock*>(o);
         LayoutPoint point(roundedLayoutPoint(transformState.mappedPoint()));
         point -= containerOffset;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderBoxModelObject.h`

```diff
@@ -79,7 +79,7 @@ class RenderBoxModelObject : public RenderObject {
 
     bool hasSelfPaintingLayer() const;
     RenderLayer* layer() const { return m_layer; }
-    virtual bool requiresLayer() const { return isRoot() || isPositioned() || isRelPositioned() || isTransparent() || hasTransform() || hasHiddenBackface() || hasMask() || hasReflection() || hasFilter() || style()->specifiesColumns(); }
+    virtual bool requiresLayer() const { return isRoot() || isOutOfFlowPositioned() || isRelPositioned() || isTransparent() || hasTransform() || hasHiddenBackface() || hasMask() || hasReflection() || hasFilter() || style()->specifiesColumns(); }
 
     // This will work on inlines to return the bounding box of all of the lines' border boxes.
     virtual IntRect borderBoundingBox() const = 0;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderDeprecatedFlexibleBox.cpp`

```diff
@@ -147,7 +147,7 @@ static LayoutUnit marginWidthForChild(RenderBox* child)
 static bool childDoesNotAffectWidthOrFlexing(RenderObject* child)
 {
     // Positioned children and collapsed children don't affect the min/max width.
-    return child->isPositioned() || child->style()->visibility() == COLLAPSE;
+    return child->isOutOfFlowPositioned() || child->style()->visibility() == COLLAPSE;
 }
 
 void RenderDeprecatedFlexibleBox::styleWillChange(StyleDifference diff, const RenderStyle* newStyle)
@@ -285,7 +285,7 @@ void RenderDeprecatedFlexibleBox::layoutBlock(bool relayoutChildren, LayoutUnit)
 
     computeRegionRangeForBlock();
 
-    if (!isFloatingOrPositioned() && height() == 0) {
+    if (!isFloatingOrOutOfFlowPositioned() && height() == 0) {
         // We are a block with no border and padding and a computed height
         // of 0.  The CSS spec states that zero-height blocks collapse their margins
         // together.
@@ -382,7 +382,7 @@ void RenderDeprecatedFlexibleBox::layoutHorizontalBox(bool relayoutChildren)
             if (relayoutChildren || (child->isReplaced() && (child->style()->width().isPercent() || child->style()->height().isPercent())))
                 child->setChildNeedsLayout(true, MarkOnlyThis);
 
-            if (child->isPositioned())
+            if (child->isOutOfFlowPositioned())
                 continue;
 
             // Compute the child's vertical margins.
@@ -430,7 +430,7 @@ void RenderDeprecatedFlexibleBox::layoutHorizontalBox(bool relayoutChildren)
         // Now that our height is actually known, we can place our boxes.
         m_stretchingChildren = (style()->boxAlign() == BSTRETCH);
         for (RenderBox* child = iterator.first(); child; child = iterator.next()) {
-            if (child->isPositioned()) {
+            if (child->isOutOfFlowPositioned()) {
                 child->containingBlock()->insertPositionedObject(child);
                 RenderLayer* childLayer = child->layer();
                 childLayer->setStaticInlinePosition(xPos); // FIXME: Not right for regions.
@@ -440,7 +440,9 @@ void RenderDeprecatedFlexibleBox::layoutHorizontalBox(bool relayoutChildren)
                         child->setChildNeedsLayout(true, MarkOnlyThis);
                 }
                 continue;
-            } else if (child->style()->visibility() == COLLAPSE) {
+            }
+            
+            if (child->style()->visibility() == COLLAPSE) {
                 // visibility: collapsed children do not participate in our positioning.
                 // But we need to lay them down.
                 child->layoutIfNeeded();
@@ -671,7 +673,7 @@ void RenderDeprecatedFlexibleBox::layoutVerticalBox(bool relayoutChildren)
             if (!haveLineClamp && (relayoutChildren || (child->isReplaced() && (child->style()->width().isPercent() || child->style()->height().isPercent()))))
                 child->setChildNeedsLayout(true, MarkOnlyThis);
 
-            if (child->isPositioned()) {
+            if (child->isOutOfFlowPositioned()) {
                 child->containingBlock()->insertPositionedObject(child);
                 RenderLayer* childLayer = child->layer();
                 childLayer->setStaticInlinePosition(borderStart() + paddingStart()); // FIXME: Not right for regions.
@@ -681,7 +683,9 @@ void RenderDeprecatedFlexibleBox::layoutVerticalBox(bool relayoutChildren)
                         child->setChildNeedsLayout(true, MarkOnlyThis);
                 }
                 continue;
-            } else if (child->style()->visibility() == COLLAPSE) {
+            }
+            
+            if (child->style()->visibility() == COLLAPSE) {
                 // visibility: collapsed children do not participate in our positioning.
                 // But we need to lay them down.
                 child->layoutIfNeeded();
@@ -1078,7 +1082,7 @@ const char *RenderDeprecatedFlexibleBox::renderName() const
 {
     if (isFloating())
         return "RenderDeprecatedFlexibleBox (floating)";
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         return "RenderDeprecatedFlexibleBox (positioned)";
     if (isAnonymous())
         return "RenderDeprecatedFlexibleBox (generated)";
```


### `third_party/WebKit/Source/WebCore/rendering/RenderFieldset.cpp`

```diff
@@ -126,7 +126,7 @@ RenderObject* RenderFieldset::layoutSpecialExcludedChild(bool relayoutChildren)
 RenderBox* RenderFieldset::findLegend() const
 {
     for (RenderObject* legend = firstChild(); legend; legend = legend->nextSibling()) {
-        if (!legend->isFloatingOrPositioned() && legend->node() && (legend->node()->hasTagName(legendTag)))
+        if (!legend->isFloatingOrOutOfFlowPositioned() && legend->node() && (legend->node()->hasTagName(legendTag)))
             return toRenderBox(legend);
     }
     return 0;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderFlexibleBox.cpp`

```diff
@@ -161,7 +161,7 @@ void RenderFlexibleBox::computePreferredLogicalWidths()
         m_minPreferredLogicalWidth = m_maxPreferredLogicalWidth = 0;
 
         for (RenderBox* child = firstChildBox(); child; child = child->nextSiblingBox()) {
-            if (child->isPositioned())
+            if (child->isOutOfFlowPositioned())
                 continue;
 
             LayoutUnit margin = marginLogicalWidthForChild(child, style());
@@ -642,7 +642,7 @@ LayoutUnit RenderFlexibleBox::autoMarginOffsetInMainAxis(const OrderedFlexItemLi
     bool isHorizontal = isHorizontalFlow();
     for (size_t i = 0; i < children.size(); ++i) {
         RenderBox* child = children[i];
-        if (child->isPositioned())
+        if (child->isOutOfFlowPositioned())
             continue;
         if (isHorizontal) {
             if (child->style()->marginLeft().isAuto())
@@ -689,7 +689,7 @@ bool RenderFlexibleBox::hasAutoMarginsInCrossAxis(RenderBox* child)
 LayoutUnit RenderFlexibleBox::availableAlignmentSpaceForChild(LayoutUnit lineCrossAxisExtent, RenderBox* child)
 {
     LayoutUnit childCrossExtent = 0;
-    if (!child->isPositioned())
+    if (!child->isOutOfFlowPositioned())
         childCrossExtent = crossAxisMarginExtentForChild(child) + crossAxisExtentForChild(child);
     return lineCrossAxisExtent - childCrossExtent;
 }
@@ -743,7 +743,7 @@ void RenderFlexibleBox::computeMainAxisPreferredSizes(bool relayoutChildren, Ord
     for (RenderBox* child = firstChildBox(); child; child = child->nextSiblingBox()) {
         orderValues.add(child->style()->order());
 
-        if (child->isPositioned())
+        if (child->isOutOfFlowPositioned())
             continue;
 
         child->clearOverrideSize();
@@ -808,7 +808,7 @@ bool RenderFlexibleBox::computeNextFlexLine(OrderIterator& iterator, OrderedFlex
     LayoutUnit lineBreak = lineBreakLength();
 
     for (RenderBox* child = iterator.currentChild(); child; child = iterator.next()) {
-        if (child->isPositioned()) {
+        if (child->isOutOfFlowPositioned()) {
             orderedChildren.append(child);
             continue;
         }
@@ -854,7 +854,7 @@ bool RenderFlexibleBox::resolveFlexibleLengths(FlexSign flexSign, const OrderedF
     WTF::Vector<Violation> maxViolations;
     for (size_t i = 0; i < children.size(); ++i) {
         RenderBox* child = children[i];
-        if (child->isPositioned()) {
+        if (child->isOutOfFlowPositioned()) {
             childSizes.append(0);
             continue;
         }
@@ -926,7 +926,7 @@ void RenderFlexibleBox::setLogicalOverrideSize(RenderBox* child, LayoutUnit chil
 
 void RenderFlexibleBox::prepareChildForPositionedLayout(RenderBox* child, LayoutUnit mainAxisOffset, LayoutUnit crossAxisOffset, PositionedLayoutMode layoutMode)
 {
-    ASSERT(child->isPositioned());
+    ASSERT(child->isOutOfFlowPositioned());
     child->containingBlock()->insertPositionedObject(child);
     RenderLayer* childLayer = child->layer();
     LayoutUnit inlinePosition = isColumnFlow() ? crossAxisOffset : mainAxisOffset;
@@ -974,7 +974,7 @@ void RenderFlexibleBox::layoutAndPlaceChildren(LayoutUnit& crossAxisOffset, cons
     bool shouldFlipMainAxis = !isColumnFlow() && !isLeftToRightFlow();
     for (size_t i = 0; i < children.size(); ++i) {
         RenderBox* child = children[i];
-        if (child->isPositioned()) {
+        if (child->isOutOfFlowPositioned()) {
             prepareChildForPositionedLayout(child, mainAxisOffset, crossAxisOffset, FlipForRowReverse);
             mainAxisOffset += justifyContentSpaceBetweenChildren(availableFreeSpace, style()->justifyContent(), childSizes.size());
             continue;
@@ -1040,7 +1040,7 @@ void RenderFlexibleBox::layoutColumnReverse(const OrderedFlexItemList& children,
 
     for (size_t i = 0; i < children.size(); ++i) {
         RenderBox* child = children[i];
-        if (child->isPositioned()) {
+        if (child->isOutOfFlowPositioned()) {
             child->layer()->setStaticBlockPosition(mainAxisOffset);
             mainAxisOffset -= justifyContentSpaceBetweenChildren(availableFreeSpace, style()->justifyContent(), childSizes.size());
             continue;
@@ -1108,7 +1108,7 @@ void RenderFlexibleBox::alignFlexLines(OrderIterator& iterator, WTF::Vector<Line
 
 void RenderFlexibleBox::adjustAlignmentForChild(RenderBox* child, LayoutUnit delta)
 {
-    if (child->isPositioned()) {
+    if (child->isOutOfFlowPositioned()) {
         LayoutUnit staticInlinePosition = child->layer()->staticInlinePosition();
         LayoutUnit staticBlockPosition = child->layer()->staticBlockPosition();
         LayoutUnit mainAxis = isColumnFlow() ? staticBlockPosition : staticInlinePosition;
@@ -1227,7 +1227,7 @@ void RenderFlexibleBox::flipForRightToLeftColumn(OrderIterator& iterator)
 
     LayoutUnit crossExtent = crossAxisExtent();
     for (RenderBox* child = iterator.first(); child; child = iterator.next()) {
-        if (child->isPositioned())
+        if (child->isOutOfFlowPositioned())
             continue;
         LayoutPoint location = flowAwareLocationForChild(child);
         location.setY(crossExtent - crossAxisExtentForChild(child) - location.y());
```


### `third_party/WebKit/Source/WebCore/rendering/RenderGrid.cpp`

```diff
@@ -50,7 +50,7 @@ const char* RenderGrid::renderName() const
 {
     if (isFloating())
         return "RenderGrid (floating)";
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         return "RenderGrid (positioned)";
     if (isAnonymous())
         return "RenderGrid (generated)";
```


### `third_party/WebKit/Source/WebCore/rendering/RenderImage.cpp`

```diff
@@ -535,7 +535,7 @@ void RenderImage::computeIntrinsicRatioInformation(FloatSize& intrinsicSize, dou
 
     // Our intrinsicSize is empty if we're rendering generated images with relative width/height. Figure out the right intrinsic size to use.
     if (intrinsicSize.isEmpty() && (m_imageResource->imageHasRelativeWidth() || m_imageResource->imageHasRelativeHeight())) {
-        RenderObject* containingBlock = isPositioned() ? container() : this->containingBlock();
+        RenderObject* containingBlock = isOutOfFlowPositioned() ? container() : this->containingBlock();
         if (containingBlock->isBox()) {
             RenderBox* box = toRenderBox(containingBlock);
             intrinsicSize.setWidth(box->availableLogicalWidth());
```


### `third_party/WebKit/Source/WebCore/rendering/RenderInline.cpp`

```diff
@@ -302,7 +302,7 @@ void RenderInline::addChildIgnoringContinuation(RenderObject* newChild, RenderOb
     if (!beforeChild && isAfterContent(lastChild()))
         beforeChild = lastChild();
 
-    if (!newChild->isInline() && !newChild->isFloatingOrPositioned()) {
+    if (!newChild->isInline() && !newChild->isFloatingOrOutOfFlowPositioned()) {
         // We are placing a block inside an inline. We have to perform a split of this
         // inline into continuations.  This involves creating an anonymous block box to hold
         // |newChild|.  We then make that block box a continuation of this inline.  We take all of
@@ -504,7 +504,7 @@ void RenderInline::addChildToContinuation(RenderObject* newChild, RenderObject*
             beforeChildParent = flow;
     }
 
-    if (newChild->isFloatingOrPositioned())
+    if (newChild->isFloatingOrOutOfFlowPositioned())
         return beforeChildParent->addChildIgnoringContinuation(newChild, beforeChild);
 
     // A continuation always consists of two potential candidates: an inline or an anonymous
@@ -555,7 +555,7 @@ void RenderInline::generateCulledLineBoxRects(GeneratorContext yield, const Rend
     bool isHorizontal = style()->isHorizontalWritingMode();
 
     for (RenderObject* curr = firstChild(); curr; curr = curr->nextSibling()) {
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue;
             
         // We want to get the margin box in the inline direction, and then use our font ascent/descent in the block
@@ -837,7 +837,7 @@ IntRect RenderInline::linesBoundingBox() const
 InlineBox* RenderInline::culledInlineFirstLineBox() const
 {
     for (RenderObject* curr = firstChild(); curr; curr = curr->nextSibling()) {
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue;
             
         // We want to get the margin box in the inline direction, and then use our font ascent/descent in the block
@@ -861,7 +861,7 @@ InlineBox* RenderInline::culledInlineFirstLineBox() const
 InlineBox* RenderInline::culledInlineLastLineBox() const
 {
     for (RenderObject* curr = lastChild(); curr; curr = curr->previousSibling()) {
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue;
             
         // We want to get the margin box in the inline direction, and then use our font ascent/descent in the block
@@ -889,7 +889,7 @@ LayoutRect RenderInline::culledInlineVisualOverflowBoundingBox() const
     LayoutRect result(enclosingLayoutRect(floatResult));
     bool isHorizontal = style()->isHorizontalWritingMode();
     for (RenderObject* curr = firstChild(); curr; curr = curr->nextSibling()) {
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue;
             
         // For overflow we just have to propagate by hand and recompute it all.
@@ -1044,7 +1044,7 @@ void RenderInline::computeRectForRepaint(RenderBoxModelObject* repaintContainer,
 
     LayoutPoint topLeft = rect.location();
 
-    if (o->isBlockFlow() && !style()->isPositioned()) {
+    if (o->isBlockFlow() && !style()->isOutOfFlowPositioned()) {
         RenderBlock* cb = toRenderBlock(o);
         if (cb->hasColumns()) {
             LayoutRect repaintRect(topLeft, rect.size());
@@ -1243,7 +1243,7 @@ void RenderInline::dirtyLineBoxes(bool fullLayout)
     if (!alwaysCreateLineBoxes()) {
         // We have to grovel into our children in order to dirty the appropriate lines.
         for (RenderObject* curr = firstChild(); curr; curr = curr->nextSibling()) {
-            if (curr->isFloatingOrPositioned())
+            if (curr->isFloatingOrOutOfFlowPositioned())
                 continue;
             if (curr->isBox() && !curr->needsLayout()) {
                 RenderBox* currBox = toRenderBox(curr);
```


### `third_party/WebKit/Source/WebCore/rendering/RenderLayer.cpp`

```diff
@@ -606,7 +606,7 @@ static bool checkContainingBlockChainForPagination(RenderBoxModelObject* rendere
         return false;
         
     // If the previous block is absolutely positioned, then we can't be paginated by the columns block.
-    if (prevBlock->isPositioned())
+    if (prevBlock->isOutOfFlowPositioned())
         return false;
         
     // Otherwise we are paginated by the columns block.
@@ -807,7 +807,7 @@ void RenderLayer::updateLayerPosition()
     // Clear our cached clip rect information.
     clearClipRects();
  
-    if (!renderer()->isPositioned() && renderer()->parent()) {
+    if (!renderer()->isOutOfFlowPositioned() && renderer()->parent()) {
         // We must adjust our position by walking up the render tree looking for the
         // nearest enclosing object with a layer.
         RenderObject* curr = renderer()->parent();
@@ -826,14 +826,14 @@ void RenderLayer::updateLayerPosition()
     }
     
     // Subtract our parent's scroll offset.
-    if (renderer()->isPositioned() && enclosingPositionedAncestor()) {
+    if (renderer()->isOutOfFlowPositioned() && enclosingPositionedAncestor()) {
         RenderLayer* positionedParent = enclosingPositionedAncestor();
 
         // For positioned layers, we subtract out the enclosing positioned layer's scroll offset.
         LayoutSize offset = positionedParent->scrolledContentOffset();
         localPoint -= offset;
         
-        if (renderer()->isPositioned() && positionedParent->renderer()->isRelPositioned() && positionedParent->renderer()->isRenderInline()) {
+        if (renderer()->isOutOfFlowPositioned() && positionedParent->renderer()->isRelPositioned() && positionedParent->renderer()->isRenderInline()) {
             LayoutSize offset = toRenderInline(positionedParent->renderer())->relativePositionedInlineOffset(toRenderBox(renderer()));
             localPoint += offset;
         }
@@ -915,7 +915,7 @@ RenderLayer* RenderLayer::stackingContext() const
 static inline bool isPositionedContainer(RenderLayer* layer)
 {
     RenderBoxModelObject* layerRenderer = layer->renderer();
-    return layer->isRootLayer() || layerRenderer->isPositioned() || layerRenderer->isRelPositioned() || layer->hasTransform();
+    return layer->isRootLayer() || layerRenderer->isOutOfFlowPositioned() || layerRenderer->isRelPositioned() || layer->hasTransform();
 }
 
 static inline bool isFixedPositionedContainer(RenderLayer* layer)
@@ -3905,7 +3905,7 @@ void RenderLayer::calculateClipRects(const RenderLayer* rootLayer, RenderRegion*
             if (renderer()->style()->hasBorderRadius())
                 newOverflowClip.setHasRadius(true);
             clipRects.setOverflowClipRect(intersection(newOverflowClip, clipRects.overflowClipRect()));
-            if (renderer()->isPositioned() || renderer()->isRelPositioned())
+            if (renderer()->isOutOfFlowPositioned() || renderer()->isRelPositioned())
                 clipRects.setPosClipRect(intersection(newOverflowClip, clipRects.posClipRect()));
         }
         if (renderer()->hasClip()) {
@@ -4701,7 +4701,7 @@ bool RenderLayer::shouldBeNormalFlowOnly() const
                 || renderer()->isApplet()
                 || renderer()->isRenderIFrame()
                 || renderer()->style()->specifiesColumns())
-            && !renderer()->isPositioned()
+            && !renderer()->isOutOfFlowPositioned()
             && !renderer()->isRelPositioned()
             && !renderer()->hasTransform()
 #if ENABLE(CSS_FILTERS)
```


### `third_party/WebKit/Source/WebCore/rendering/RenderLayerCompositor.cpp`

```diff
@@ -1813,7 +1813,7 @@ bool RenderLayerCompositor::requiresCompositingForPosition(RenderObject* rendere
     // position:fixed elements that create their own stacking context (e.g. have an explicit z-index,
     // opacity, transform) can get their own composited layer. A stacking context is required otherwise
     // z-index and clipping will be broken.
-    if (!(renderer->isPositioned() && renderer->style()->position() == FixedPosition && layer->isStackingContext()))
+    if (!(renderer->isOutOfFlowPositioned() && renderer->style()->position() == FixedPosition && layer->isStackingContext()))
         return false;
 
     if (Settings* settings = m_renderView->document()->settings())
```


### `third_party/WebKit/Source/WebCore/rendering/RenderLineBoxList.cpp`

```diff
@@ -334,7 +334,7 @@ void RenderLineBoxList::dirtyLinesFromChangedChild(RenderObject* container, Rend
     RootInlineBox* box = 0;
     RenderObject* curr = 0;
     for (curr = child->previousSibling(); curr; curr = curr->previousSibling()) {
-        if (curr->isFloatingOrPositioned())
+        if (curr->isFloatingOrOutOfFlowPositioned())
             continue;
 
         if (curr->isReplaced()) {
```


### `third_party/WebKit/Source/WebCore/rendering/RenderListItem.cpp`

```diff
@@ -189,7 +189,7 @@ static RenderObject* getParentOfFirstLineBox(RenderBlock* curr, RenderObject* ma
         if (currChild->isInline() && (!currChild->isRenderInline() || curr->generatesLineBoxesForInlineChild(currChild)))
             return curr;
 
-        if (currChild->isFloating() || currChild->isPositioned())
+        if (currChild->isFloating() || currChild->isOutOfFlowPositioned())
             continue;
 
         if (currChild->isTable() || !currChild->isRenderBlock() || (currChild->isBox() && toRenderBox(currChild)->isWritingModeRoot()))
```


### `third_party/WebKit/Source/WebCore/rendering/RenderMultiColumnBlock.cpp`

```diff
@@ -152,7 +152,7 @@ const char* RenderMultiColumnBlock::renderName() const
 {    
     if (isFloating())
         return "RenderMultiColumnBlock (floating)";
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         return "RenderMultiColumnBlock (positioned)";
     if (isAnonymousBlock())
         return "RenderMultiColumnBlock (anonymous)";
```


### `third_party/WebKit/Source/WebCore/rendering/RenderObject.cpp`

```diff
@@ -641,7 +641,7 @@ void RenderObject::markContainingBlocksForLayout(bool scheduleRelayout, RenderOb
         RenderObject* container = object->container();
         if (!container && !object->isRenderView())
             return;
-        if (!last->isText() && last->style()->isPositioned()) {
+        if (!last->isText() && last->style()->isOutOfFlowPositioned()) {
             bool willSkipRelativelyPositionedInlines = !object->isRenderBlock() || object->isAnonymousBlock();
             // Skip relatively positioned inlines and anonymous blocks to get to the enclosing RenderBlock.
             while (object && (!object->isRenderBlock() || object->isAnonymousBlock()))
@@ -682,7 +682,7 @@ void RenderObject::setPreferredLogicalWidthsDirty(bool shouldBeDirty, MarkingBeh
 {
     bool alreadyDirty = preferredLogicalWidthsDirty();
     m_bitfields.setPreferredLogicalWidthsDirty(shouldBeDirty);
-    if (shouldBeDirty && !alreadyDirty && markParents == MarkContainingBlockChain && (isText() || !style()->isPositioned()))
+    if (shouldBeDirty && !alreadyDirty && markParents == MarkContainingBlockChain && (isText() || !style()->isOutOfFlowPositioned()))
         invalidateContainerPreferredLogicalWidths();
 }
 
@@ -699,7 +699,7 @@ void RenderObject::invalidateContainerPreferredLogicalWidths()
             break;
 
         o->m_bitfields.setPreferredLogicalWidthsDirty(true);
-        if (o->style()->isPositioned())
+        if (o->style()->isOutOfFlowPositioned())
             // A positioned object has no effect on the min/max width of its containing block ever.
             // We can optimize this case and not go up any further.
             break;
@@ -1806,13 +1806,13 @@ void RenderObject::styleWillChange(StyleDifference diff, const RenderStyle* newS
             // For changes in float styles, we need to conceivably remove ourselves
             // from the floating objects list.
             toRenderBox(this)->removeFloatingOrPositionedChildFromBlockLists();
-        else if (isPositioned() && (m_style->position() != newStyle->position()))
+        else if (isOutOfFlowPositioned() && (m_style->position() != newStyle->position()))
             // For changes in positioning styles, we need to conceivably remove ourselves
             // from the positioned objects list.
             toRenderBox(this)->removeFloatingOrPositionedChildFromBlockLists();
 
-        s_affectsParentBlock = isFloatingOrPositioned() &&
-            (!newStyle->isFloating() && newStyle->position() != AbsolutePosition && newStyle->position() != FixedPosition)
+        s_affectsParentBlock = isFloatingOrOutOfFlowPositioned()
+            && (!newStyle->isFloating() && newStyle->position() != AbsolutePosition && newStyle->position() != FixedPosition)
             && parent() && (parent()->isBlockFlow() || parent()->isRenderInline());
 
         // reset style flags
@@ -2747,7 +2747,7 @@ RenderBoxModelObject* RenderObject::offsetParent() const
     // A is the root element.
     // A is the HTML body element.
     // The computed value of the position property for element A is fixed.
-    if (isRoot() || isBody() || (isPositioned() && style()->position() == FixedPosition))
+    if (isRoot() || isBody() || (isOutOfFlowPositioned() && style()->position() == FixedPosition))
         return 0;
 
     // If A is an area HTML element which has a map HTML element somewhere in the ancestor
@@ -2762,10 +2762,10 @@ RenderBoxModelObject* RenderObject::offsetParent() const
     //       is one of the following HTML elements: td, th, or table.
     //     * Our own extension: if there is a difference in the effective zoom
 
-    bool skipTables = isPositioned() || isRelPositioned();
+    bool skipTables = isOutOfFlowPositioned() || isRelPositioned();
     float currZoom = style()->effectiveZoom();
     RenderObject* curr = parent();
-    while (curr && (!curr->node() || (!curr->isPositioned() && !curr->isRelPositioned() && !curr->isBody()))) {
+    while (curr && (!curr->node() || (!curr->isOutOfFlowPositioned() && !curr->isRelPositioned() && !curr->isBody()))) {
         Node* element = curr->node();
         if (!skipTables && element && (element->hasTagName(tableTag) || element->hasTagName(tdTag) || element->hasTagName(thTag)))
             break;
```


### `third_party/WebKit/Source/WebCore/rendering/RenderObject.h`

```diff
@@ -500,7 +500,8 @@ class RenderObject : public CachedImageClient {
     virtual RenderBoxModelObject* virtualContinuation() const { return 0; }
 
     bool isFloating() const { return m_bitfields.floating(); }
-    bool isPositioned() const { return m_bitfields.positioned(); } // absolute or fixed positioning
+    bool isOutOfFlowPositioned() const { return m_bitfields.positioned(); } // absolute or fixed positioning
+    bool isInFlowPositioned() const { return m_bitfields.relPositioned(); } // relative positioning
     bool isRelPositioned() const { return m_bitfields.relPositioned(); } // relative positioning
     bool isText() const  { return m_bitfields.isText(); }
     bool isBox() const { return m_bitfields.isBox(); }
@@ -538,7 +539,7 @@ class RenderObject : public CachedImageClient {
 
     bool isSelectionBorder() const;
 
-    bool hasClip() const { return isPositioned() && style()->hasClip(); }
+    bool hasClip() const { return isOutOfFlowPositioned() && style()->hasClip(); }
     bool hasOverflowClip() const { return m_bitfields.hasOverflowClip(); }
 
     bool hasTransform() const { return m_bitfields.hasTransform(); }
@@ -780,7 +781,7 @@ class RenderObject : public CachedImageClient {
 
     virtual unsigned int length() const { return 1; }
 
-    bool isFloatingOrPositioned() const { return (isFloating() || isPositioned()); }
+    bool isFloatingOrOutOfFlowPositioned() const { return (isFloating() || isOutOfFlowPositioned()); }
 
     bool isTransparent() const { return style()->opacity() < 1.0f; }
     float opacity() const { return style()->opacity(); }
```


### `third_party/WebKit/Source/WebCore/rendering/RenderObjectChildList.cpp`

```diff
@@ -75,7 +75,7 @@ RenderObject* RenderObjectChildList::removeChildNode(RenderObject* owner, Render
 {
     ASSERT(oldChild->parent() == owner);
 
-    if (oldChild->isFloatingOrPositioned())
+    if (oldChild->isFloatingOrOutOfFlowPositioned())
         toRenderBox(oldChild)->removeFloatingOrPositionedChildFromBlockLists();
 
     // So that we'll get the appropriate dirty bit set (either that a normal flow child got yanked or
@@ -111,7 +111,7 @@ RenderObject* RenderObjectChildList::removeChildNode(RenderObject* owner, Render
         if (oldChild->isListItem())
             toRenderListItem(oldChild)->updateListMarkerNumbers();
 
-        if (oldChild->isPositioned() && owner->childrenInline())
+        if (oldChild->isOutOfFlowPositioned() && owner->childrenInline())
             owner->dirtyLinesFromChangedChild(oldChild);
 
         if (oldChild->isRenderRegion())
```


### `third_party/WebKit/Source/WebCore/rendering/RenderReplaced.cpp`

```diff
@@ -238,7 +238,7 @@ static inline bool hasAutoHeightOrContainingBlockWithAutoHeight(const RenderRepl
     // For percentage heights: The percentage is calculated with respect to the height of the generated box's
     // containing block. If the height of the containing block is not specified explicitly (i.e., it depends
     // on content height), and this element is not absolutely positioned, the value computes to 'auto'.
-    if (!logicalHeightLength.isPercent() || replaced->isPositioned() || replaced->document()->inQuirksMode())
+    if (!logicalHeightLength.isPercent() || replaced->isOutOfFlowPositioned() || replaced->document()->inQuirksMode())
         return false;
 
     for (RenderBlock* cb = replaced->containingBlock(); !cb->isRenderView(); cb = cb->containingBlock()) {
```


### `third_party/WebKit/Source/WebCore/rendering/RenderRubyRun.cpp`

```diff
@@ -76,7 +76,7 @@ RenderRubyText* RenderRubyRun::rubyText() const
     RenderObject* child = firstChild();
     // If in future it becomes necessary to support floating or positioned ruby text,
     // layout will have to be changed to handle them properly.
-    ASSERT(!child || !child->isRubyText() || !child->isFloatingOrPositioned());
+    ASSERT(!child || !child->isRubyText() || !child->isFloatingOrOutOfFlowPositioned());
     return child && child->isRubyText() ? static_cast<RenderRubyText*>(child) : 0;
 }
 
```


### `third_party/WebKit/Source/WebCore/rendering/RenderTable.cpp`

```diff
@@ -114,7 +114,7 @@ void RenderTable::addChild(RenderObject* child, RenderObject* beforeChild)
     if (!beforeChild)
         beforeChild = afterPseudoElementRenderer();
 
-    bool wrapInAnonymousSection = !child->isPositioned();
+    bool wrapInAnonymousSection = !child->isOutOfFlowPositioned();
 
     if (child->isTableCaption()) {
         m_captions.append(toRenderTableCaption(child));
@@ -213,7 +213,7 @@ void RenderTable::computeLogicalWidth()
 {
     recalcSectionsIfNeeded();
 
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         computePositionedLogicalWidth();
 
     RenderBlock* cb = containingBlock();
@@ -390,7 +390,7 @@ void RenderTable::layout()
 
     setLogicalHeight(logicalHeight() + borderAndPaddingBefore);
 
-    if (!isPositioned())
+    if (!isOutOfFlowPositioned())
         computeLogicalHeight();
 
     Length logicalHeightLength = style()->logicalHeight();
@@ -439,7 +439,7 @@ void RenderTable::layout()
         layoutCaption(m_captions[i]);
     }
 
-    if (isPositioned())
+    if (isOutOfFlowPositioned())
         computeLogicalHeight();
 
     // table can be containing block of positioned elements.
```


### `third_party/WebKit/Source/WebCore/rendering/style/RenderStyle.h`

```diff
@@ -521,7 +521,7 @@ class RenderStyle: public RefCounted<RenderStyle> {
     bool hasStaticBlockPosition(bool horizontal) const { return horizontal ? hasAutoTopAndBottom() : hasAutoLeftAndRight(); }
 
     EPosition position() const { return static_cast<EPosition>(noninherited_flags._position); }
-    bool isPositioned() const { return position() == AbsolutePosition || position() == FixedPosition; }
+    bool isOutOfFlowPositioned() const { return position() == AbsolutePosition || position() == FixedPosition; }
     EFloat floating() const { return static_cast<EFloat>(noninherited_flags._floating); }
 
     Length width() const { return m_box->width(); }
```


### `third_party/WebKit/Source/WebKit/blackberry/Api/WebPage.cpp`

```diff
@@ -2506,7 +2506,7 @@ typedef bool (*PredicateFunction)(RenderLayer*);
 static bool isPositionedContainer(RenderLayer* layer)
 {
     RenderObject* o = layer->renderer();
-    return o->isRenderView() || o->isPositioned() || o->isRelPositioned() || layer->hasTransform();
+    return o->isRenderView() || o->isOutOfFlowPositioned() || o->isRelPositioned() || layer->hasTransform();
 }
 
 static bool isNonRenderViewFixedPositionedContainer(RenderLayer* layer)
@@ -2515,13 +2515,13 @@ static bool isNonRenderViewFixedPositionedContainer(RenderLayer* layer)
     if (o->isRenderView())
         return false;
 
-    return o->isPositioned() && o->style()->position() == FixedPosition;
+    return o->isOutOfFlowPositioned() && o->style()->position() == FixedPosition;
 }
 
 static bool isFixedPositionedContainer(RenderLayer* layer)
 {
     RenderObject* o = layer->renderer();
-    return o->isRenderView() || (o->isPositioned() && o->style()->position() == FixedPosition);
+    return o->isRenderView() || (o->isOutOfFlowPositioned() && o->style()->position() == FixedPosition);
 }
 
 static RenderLayer* findAncestorOrSelfNotMatching(PredicateFunction predicate, RenderLayer* layer)
```


### `third_party/WebKit/Source/WebKit/blackberry/ChangeLog`

```diff
@@ -1,3 +1,22 @@
+2012-06-24  Simon Fraser  <simon.fraser@apple.com>
+
+        Rename isPositioned to isOutOfFlowPositioned for clarity
+        [url removida]
+
+        Reviewed by Antti Koivisto.
+        
+        RenderObject and RenderStyle had an isPositioned() method that was
+        confusing, because it excluded relative positioning. Rename to 
+        isOutOfFlowPositioned(), which makes it clearer that it only applies
+        to absolute and fixed positioning.
+
+        Simple rename; no behavior change.
+
+        * Api/WebPage.cpp:
+        (BlackBerry::WebKit::isPositionedContainer):
+        (BlackBerry::WebKit::isNonRenderViewFixedPositionedContainer):
+        (BlackBerry::WebKit::isFixedPositionedContainer):
+
 2012-06-23  Sheriff Bot  <webkit.review.bot@gmail.com>
 
         Unreviewed, rolling out r121058.
```


### `third_party/WebKit/Source/WebKit2/ChangeLog`

```diff
@@ -1,3 +1,20 @@
+2012-06-24  Simon Fraser  <simon.fraser@apple.com>
+
+        Rename isPositioned to isOutOfFlowPositioned for clarity
+        [url removida]
+
+        Reviewed by Antti Koivisto.
+        
+        RenderObject and RenderStyle had an isPositioned() method that was
+        confusing, because it excluded relative positioning. Rename to 
+        isOutOfFlowPositioned(), which makes it clearer that it only applies
+        to absolute and fixed positioning.
+
+        Simple rename; no behavior change.
+
+        * WebProcess/WebPage/qt/LayerTreeHostQt.cpp:
+        (WebKit::updateOffsetFromViewportForSelf):
+
 2012-06-24  Andreas Kling  <kling@webkit.org>
 
         REGRESSION(r120329): Intermittent WebProcess shutdowns due to out-of-line DidReceiveEvent messages.
```


### `third_party/WebKit/Source/WebKit2/WebProcess/WebPage/qt/LayerTreeHostQt.cpp`

```diff
@@ -297,7 +297,7 @@ static void updateOffsetFromViewportForSelf(RenderLayer* renderLayer)
     if (!style)
         return;
 
-    if (!renderLayer->renderer()->isPositioned() || renderLayer->renderer()->style()->position() != FixedPosition)
+    if (!renderLayer->renderer()->isOutOfFlowPositioned() || renderLayer->renderer()->style()->position() != FixedPosition)
         return;
 
     if (!renderLayer->renderer()->container()->isRenderView())
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
