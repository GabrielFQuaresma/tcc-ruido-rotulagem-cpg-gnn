# Pacote de anotacao — caso 24

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

# Evidencia do caso 24

## Identificacao

- projeto: Android
- CVE: CVE-2015-3842
- CWE atribuida pelo BigVul: CWE-119
- commit: `aeea52da00d210587fb3ed895de3d5f2e0264c88`
- URL do commit: https://android.googlesource.com/platform/frameworks/av/+/aeea52da00d210587fb3ed895de3d5f2e0264c88
- arquivo da funcao marcada: `media/libeffects/loudness/EffectLoudnessEnhancer.cpp`

## Mensagem do commit

> audio effects: fix heap overflow
> 
> Check consistency of effect command reply sizes before
> copying to reply address.
> 
> Also add null pointer check on reply size.
> Also remove unused parameter warning.
> 
> Bug: 21953516.
> Change-Id: I4cf00c12eaed696af28f3b7613f7e36f47a160c4
> (cherry picked from commit 0f714a464d2425afe00d6450535e763131b40844)
> 

## Resumo da CVE

> Multiple heap-based buffer overflows in libeffects in the Audio Policy Service in mediaserver in Android before 5.1.1 LMY48I allow attackers to execute arbitrary code via a crafted application, aka internal bug 21953516.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -18,7 +18,7 @@
          break;
      case EFFECT_CMD_SET_CONFIG:
          if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
-                || pReplyData == NULL || *replySize != sizeof(int)) {
+                || pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
              return -EINVAL;
          }
          *(int *) pReplyData = LE_setConfig(pContext,
@@ -36,7 +36,7 @@
          LE_reset(pContext);
          break;
      case EFFECT_CMD_ENABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
              return -EINVAL;
          }
          if (pContext->mState != LOUDNESS_ENHANCER_STATE_INITIALIZED) {
@@ -61,7 +61,7 @@
      case EFFECT_CMD_GET_PARAM: {
          if (pCmdData == NULL ||
              cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL ||
+            pReplyData == NULL || replySize == NULL ||
              *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
              return -EINVAL;
          }
@@ -88,7 +88,7 @@
      case EFFECT_CMD_SET_PARAM: {
          if (pCmdData == NULL ||
              cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL || *replySize != sizeof(int32_t)) {
+            pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
              return -EINVAL;
          }
          *(int32_t *)pReplyData = 0;
```

## Corpo completo da funcao antes da correcao

```c
int LE_command(effect_handle_t self, uint32_t cmdCode, uint32_t cmdSize,
 void *pCmdData, uint32_t *replySize, void *pReplyData) {

 LoudnessEnhancerContext * pContext = (LoudnessEnhancerContext *)self;
 int retsize;

 if (pContext == NULL || pContext->mState == LOUDNESS_ENHANCER_STATE_UNINITIALIZED) {
 return -EINVAL;
 }

 switch (cmdCode) {
 case EFFECT_CMD_INIT:
 if (pReplyData == NULL || *replySize != sizeof(int)) {
 return -EINVAL;
 }
 *(int *) pReplyData = LE_init(pContext);

         break;
     case EFFECT_CMD_SET_CONFIG:
         if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
                || pReplyData == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = LE_setConfig(pContext,
 (effect_config_t *) pCmdData);
 break;
 case EFFECT_CMD_GET_CONFIG:
 if (pReplyData == NULL ||
 *replySize != sizeof(effect_config_t)) {
 return -EINVAL;
 }
        LE_getConfig(pContext, (effect_config_t *)pReplyData);
 break;
 case EFFECT_CMD_RESET:

         LE_reset(pContext);
         break;
     case EFFECT_CMD_ENABLE:
        if (pReplyData == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pContext->mState != LOUDNESS_ENHANCER_STATE_INITIALIZED) {
 return -ENOSYS;
 }
        pContext->mState = LOUDNESS_ENHANCER_STATE_ACTIVE;
        ALOGV("EFFECT_CMD_ENABLE() OK");
 *(int *)pReplyData = 0;
 break;
 case EFFECT_CMD_DISABLE:
 if (pReplyData == NULL || *replySize != sizeof(int)) {
 return -EINVAL;
 }
 if (pContext->mState != LOUDNESS_ENHANCER_STATE_ACTIVE) {
 return -ENOSYS;
 }
        pContext->mState = LOUDNESS_ENHANCER_STATE_INITIALIZED;
        ALOGV("EFFECT_CMD_DISABLE() OK");
 *(int *)pReplyData = 0;
 break;

     case EFFECT_CMD_GET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t)) ||
            pReplyData == NULL ||
             *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
             return -EINVAL;
         }
        memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + sizeof(uint32_t));
 effect_param_t *p = (effect_param_t *)pReplyData;
        p->status = 0;
 *replySize = sizeof(effect_param_t) + sizeof(uint32_t);
 if (p->psize != sizeof(uint32_t)) {
            p->status = -EINVAL;
 break;
 }
 switch (*(uint32_t *)p->data) {
 case LOUDNESS_ENHANCER_PARAM_TARGET_GAIN_MB:
            ALOGV("get target gain(mB) = %d", pContext->mTargetGainmB);
 *((int32_t *)p->data + 1) = pContext->mTargetGainmB;
            p->vsize = sizeof(int32_t);
 *replySize += sizeof(int32_t);
 break;
 default:
            p->status = -EINVAL;
 }
 } break;

     case EFFECT_CMD_SET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t)) ||
            pReplyData == NULL || *replySize != sizeof(int32_t)) {
             return -EINVAL;
         }
         *(int32_t *)pReplyData = 0;
 effect_param_t *p = (effect_param_t *)pCmdData;
 if (p->psize != sizeof(uint32_t) || p->vsize != sizeof(uint32_t)) {
 *(int32_t *)pReplyData = -EINVAL;
 break;
 }
 switch (*(uint32_t *)p->data) {
 case LOUDNESS_ENHANCER_PARAM_TARGET_GAIN_MB:
            pContext->mTargetGainmB = *((int32_t *)p->data + 1);
            ALOGV("set target gain(mB) = %d", pContext->mTargetGainmB);
            LE_reset(pContext); // apply parameter update
 break;
 default:
 *(int32_t *)pReplyData = -EINVAL;
 }
 } break;
 case EFFECT_CMD_SET_DEVICE:
 case EFFECT_CMD_SET_VOLUME:
 case EFFECT_CMD_SET_AUDIO_MODE:
 break;

 default:
        ALOGW("LE_command invalid command %d",cmdCode);
 return -EINVAL;
 }

 return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **6**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `media/libeffects/downmix/EffectDownmix.c` |  |  |  |
| `media/libeffects/loudness/EffectLoudnessEnhancer.cpp` **(funcao marcada esta aqui)** |  |  |  |
| `media/libeffects/lvm/wrapper/Bundle/EffectBundle.cpp` |  |  |  |
| `media/libeffects/lvm/wrapper/Reverb/EffectReverb.cpp` |  |  |  |
| `media/libeffects/preprocessing/PreProcessing.cpp` |  |  |  |
| `media/libeffects/visualizer/EffectVisualizer.cpp` |  |  |  |


### `media/libeffects/loudness/EffectLoudnessEnhancer.cpp`

```diff
@@ -189,8 +189,8 @@

 //
 
 int LELib_Create(const effect_uuid_t *uuid,
-                         int32_t sessionId,
-                         int32_t ioId,
+                         int32_t sessionId __unused,
+                         int32_t ioId __unused,
                          effect_handle_t *pHandle) {
     ALOGV("LELib_Create()");
     int ret;
@@ -327,7 +327,7 @@

         break;
     case EFFECT_CMD_SET_CONFIG:
         if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
-                || pReplyData == NULL || *replySize != sizeof(int)) {
+                || pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = LE_setConfig(pContext,
@@ -344,7 +344,7 @@

         LE_reset(pContext);
         break;
     case EFFECT_CMD_ENABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pContext->mState != LOUDNESS_ENHANCER_STATE_INITIALIZED) {
@@ -368,7 +368,7 @@

     case EFFECT_CMD_GET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL ||
+            pReplyData == NULL || replySize == NULL ||
             *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
             return -EINVAL;
         }
@@ -394,7 +394,7 @@

     case EFFECT_CMD_SET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL || *replySize != sizeof(int32_t)) {
+            pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
             return -EINVAL;
         }
         *(int32_t *)pReplyData = 0;

```


### `media/libeffects/downmix/EffectDownmix.c`

```diff
@@ -149,8 +149,8 @@

 /*--- Effect Library Interface Implementation ---*/
 
 int32_t DownmixLib_Create(const effect_uuid_t *uuid,
-        int32_t sessionId,
-        int32_t ioId,
+        int32_t sessionId __unused,
+        int32_t ioId __unused,
         effect_handle_t *pHandle) {
     int ret;
     int i;
@@ -370,7 +370,7 @@

 
     switch (cmdCode) {
     case EFFECT_CMD_INIT:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = Downmix_Init(pDwmModule);
@@ -378,7 +378,7 @@

 
     case EFFECT_CMD_SET_CONFIG:
         if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
-                || pReplyData == NULL || *replySize != sizeof(int)) {
+                || pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = Downmix_Configure(pDwmModule,
@@ -393,7 +393,7 @@

         ALOGV("Downmix_Command EFFECT_CMD_GET_PARAM pCmdData %p, *replySize %" PRIu32 ", pReplyData: %p",
                 pCmdData, *replySize, pReplyData);
         if (pCmdData == NULL || cmdSize < (int)(sizeof(effect_param_t) + sizeof(int32_t)) ||
-                pReplyData == NULL ||
+                pReplyData == NULL || replySize == NULL ||
                 *replySize < (int) sizeof(effect_param_t) + 2 * sizeof(int32_t)) {
             return -EINVAL;
         }
@@ -410,7 +410,7 @@

         ALOGV("Downmix_Command EFFECT_CMD_SET_PARAM cmdSize %d pCmdData %p, *replySize %" PRIu32
                 ", pReplyData %p", cmdSize, pCmdData, *replySize, pReplyData);
         if (pCmdData == NULL || (cmdSize < (int)(sizeof(effect_param_t) + sizeof(int32_t)))
-                || pReplyData == NULL || *replySize != (int)sizeof(int32_t)) {
+                || pReplyData == NULL || replySize == NULL || *replySize != (int)sizeof(int32_t)) {
             return -EINVAL;
         }
         effect_param_t *cmd = (effect_param_t *) pCmdData;
@@ -429,7 +429,7 @@

         break;
 
     case EFFECT_CMD_ENABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pDownmixer->state != DOWNMIX_STATE_INITIALIZED) {
@@ -441,7 +441,7 @@

         break;
 
     case EFFECT_CMD_DISABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pDownmixer->state != DOWNMIX_STATE_ACTIVE) {
@@ -659,7 +659,7 @@

  *----------------------------------------------------------------------------
  */
 
-int Downmix_Reset(downmix_object_t *pDownmixer, bool init) {
+int Downmix_Reset(downmix_object_t *pDownmixer __unused, bool init __unused) {
     // nothing to do here
     return 0;
 }

```


### `media/libeffects/lvm/wrapper/Bundle/EffectBundle.cpp`

```diff
@@ -2996,7 +2996,7 @@

 
     switch (cmdCode){
         case EFFECT_CMD_INIT:
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)){
                 ALOGV("\tLVM_ERROR, EFFECT_CMD_INIT: ERROR for effect type %d",
                         pContext->EffectType);
                 return -EINVAL;
@@ -3023,10 +3023,8 @@

 
         case EFFECT_CMD_SET_CONFIG:
             //ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_SET_CONFIG start");
-            if (pCmdData    == NULL||
-                cmdSize     != sizeof(effect_config_t)||
-                pReplyData  == NULL||
-                *replySize  != sizeof(int)){
+            if (pCmdData    == NULL || cmdSize     != sizeof(effect_config_t) ||
+                    pReplyData  == NULL || replySize == NULL || *replySize  != sizeof(int)) {
                 ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: "
                         "EFFECT_CMD_SET_CONFIG: ERROR");
                 return -EINVAL;
@@ -3036,8 +3034,7 @@

             break;
 
         case EFFECT_CMD_GET_CONFIG:
-            if (pReplyData == NULL ||
-                *replySize != sizeof(effect_config_t)) {
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(effect_config_t)) {
                 ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: "
                         "EFFECT_CMD_GET_CONFIG: ERROR");
                 return -EINVAL;
@@ -3055,30 +3052,27 @@

         case EFFECT_CMD_GET_PARAM:{
             //ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_GET_PARAM start");
 
+            effect_param_t *p = (effect_param_t *)pCmdData;
+
+            if (pCmdData == NULL || cmdSize < sizeof(effect_param_t) ||
+                    cmdSize < (sizeof(effect_param_t) + p->psize) ||
+                    pReplyData == NULL || replySize == NULL ||
+                    *replySize < (sizeof(effect_param_t) + p->psize)) {
+                ALOGV("\tLVM_ERROR : EFFECT_CMD_GET_PARAM: ERROR");
+                return -EINVAL;
+            }
+
+            memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
+
+            p = (effect_param_t *)pReplyData;
+
+            int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);
+
             if(pContext->EffectType == LVM_BASS_BOOST){
-                if (pCmdData == NULL ||
-                        cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                        pReplyData == NULL ||
-                        *replySize < (sizeof(effect_param_t) + sizeof(int32_t))){
-                    ALOGV("\tLVM_ERROR : BassBoost_command cmdCode Case: "
-                            "EFFECT_CMD_GET_PARAM: ERROR");
-                    return -EINVAL;
-                }
-                effect_param_t *p = (effect_param_t *)pCmdData;
-
-                memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
-
-                p = (effect_param_t *)pReplyData;
-
-                int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);
-
                 p->status = android::BassBoost_getParameter(pContext,
                                                             p->data,
                                                             &p->vsize,
                                                             p->data + voffset);
-
-                *replySize = sizeof(effect_param_t) + voffset + p->vsize;
-
                 //ALOGV("\tBassBoost_command EFFECT_CMD_GET_PARAM "
                 //        "*pCmdData %d, *replySize %d, *pReplyData %d ",
                 //        *(int32_t *)((char *)pCmdData + sizeof(effect_param_t)),
@@ -3087,27 +3081,10 @@

             }
 
             if(pContext->EffectType == LVM_VIRTUALIZER){
-                if (pCmdData == NULL ||
-                        cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                        pReplyData == NULL ||
-                        *replySize < (sizeof(effect_param_t) + sizeof(int32_t))){
-                    ALOGV("\tLVM_ERROR : Virtualizer_command cmdCode Case: "
-                            "EFFECT_CMD_GET_PARAM: ERROR");
-                    return -EINVAL;
-                }
-                effect_param_t *p = (effect_param_t *)pCmdData;
-
-                memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
-
-                p = (effect_param_t *)pReplyData;
-
-                int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);
-
                 p->status = android::Virtualizer_getParameter(pContext,
                                                               (void *)p->data,
                                                               &p->vsize,
                                                               p->data + voffset);
-                *replySize = sizeof(effect_param_t) + voffset + p->vsize;
 
                 //ALOGV("\tVirtualizer_command EFFECT_CMD_GET_PARAM "
                 //        "*pCmdData %d, *replySize %d, *pReplyData %d ",
@@ -3118,29 +3095,11 @@

             if(pContext->EffectType == LVM_EQUALIZER){
                 //ALOGV("\tEqualizer_command cmdCode Case: "
                 //        "EFFECT_CMD_GET_PARAM start");
-                if (pCmdData == NULL ||
-                    cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                    pReplyData == NULL ||
-                    *replySize < (int) (sizeof(effect_param_t) + sizeof(int32_t))) {
-                    ALOGV("\tLVM_ERROR : Equalizer_command cmdCode Case: "
-                            "EFFECT_CMD_GET_PARAM");
-                    return -EINVAL;
-                }
-                effect_param_t *p = (effect_param_t *)pCmdData;
-
-                memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
-
-                p = (effect_param_t *)pReplyData;
-
-                int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);
-
                 p->status = android::Equalizer_getParameter(pContext,
                                                             p->data,
                                                             &p->vsize,
                                                             p->data + voffset);
 
-                *replySize = sizeof(effect_param_t) + voffset + p->vsize;
-
                 //ALOGV("\tEqualizer_command EFFECT_CMD_GET_PARAM *pCmdData %d, *replySize %d, "
                 //       "*pReplyData %08x %08x",
                 //        *(int32_t *)((char *)pCmdData + sizeof(effect_param_t)), *replySize,
@@ -3150,35 +3109,19 @@

             }
             if(pContext->EffectType == LVM_VOLUME){
                 //ALOGV("\tVolume_command cmdCode Case: EFFECT_CMD_GET_PARAM start");
-                if (pCmdData == NULL ||
-                        cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                        pReplyData == NULL ||
-                        *replySize < (int) (sizeof(effect_param_t) + sizeof(int32_t))){
-                    ALOGV("\tLVM_ERROR : Volume_command cmdCode Case: "
-                            "EFFECT_CMD_GET_PARAM: ERROR");
-                    return -EINVAL;
-                }
-                effect_param_t *p = (effect_param_t *)pCmdData;
-
-                memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
-
-                p = (effect_param_t *)pReplyData;
-
-                int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);
-
                 p->status = android::Volume_getParameter(pContext,
                                                          (void *)p->data,
                                                          &p->vsize,
                                                          p->data + voffset);
 
-                *replySize = sizeof(effect_param_t) + voffset + p->vsize;
-
                 //ALOGV("\tVolume_command EFFECT_CMD_GET_PARAM "
                 //        "*pCmdData %d, *replySize %d, *pReplyData %d ",
                 //        *(int32_t *)((char *)pCmdData + sizeof(effect_param_t)),
                 //        *replySize,
                 //        *(int16_t *)((char *)pReplyData + sizeof(effect_param_t) + voffset));
             }
+            *replySize = sizeof(effect_param_t) + voffset + p->vsize;
+
             //ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_GET_PARAM end");
         } break;
         case EFFECT_CMD_SET_PARAM:{
@@ -3189,10 +3132,9 @@

                 //       *replySize,
                 //       *(int16_t *)((char *)pCmdData + sizeof(effect_param_t) + sizeof(int32_t)));
 
-                if (pCmdData   == NULL||
-                    cmdSize    != (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int16_t))||
-                    pReplyData == NULL||
-                    *replySize != sizeof(int32_t)){
+                if (pCmdData   == NULL ||
+                        cmdSize    != (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int16_t)) ||
+                        pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
                     ALOGV("\tLVM_ERROR : BassBoost_command cmdCode Case: "
                             "EFFECT_CMD_SET_PARAM: ERROR");
                     return -EINVAL;
@@ -3224,11 +3166,10 @@

               //        *(int16_t *)((char *)pCmdData + sizeof(effect_param_t) + sizeof(int32_t)));
 
                 if (pCmdData   == NULL ||
-                    // legal parameters are int16_t or int32_t
-                    cmdSize    > (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int32_t)) ||
-                    cmdSize    < (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int16_t)) ||
-                    pReplyData == NULL ||
-                    *replySize != sizeof(int32_t)){
+                        // legal parameters are int16_t or int32_t
+                        cmdSize    > (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int32_t)) ||
+                        cmdSize    < (sizeof(effect_param_t) + sizeof(int32_t) +sizeof(int16_t)) ||
+                        pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
                     ALOGV("\tLVM_ERROR : Virtualizer_command cmdCode Case: "
                             "EFFECT_CMD_SET_PARAM: ERROR");
                     return -EINVAL;
@@ -3261,7 +3202,7 @@

                //        *(int16_t *)((char *)pCmdData + sizeof(effect_param_t) + sizeof(int32_t)));
 
                 if (pCmdData == NULL || cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                    pReplyData == NULL || *replySize != sizeof(int32_t)) {
+                        pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
                     ALOGV("\tLVM_ERROR : Equalizer_command cmdCode Case: "
                             "EFFECT_CMD_SET_PARAM: ERROR");
                     return -EINVAL;
@@ -3279,10 +3220,10 @@

                 //        *replySize,
                 //        *(int16_t *)((char *)pCmdData + sizeof(effect_param_t) +sizeof(int32_t)));
 
-                if (    pCmdData   == NULL||
-                        cmdSize    < (sizeof(effect_param_t) + sizeof(int32_t))||
-                        pReplyData == NULL||
-                        *replySize != sizeof(int32_t)){
+                if (pCmdData   == NULL ||
+                        cmdSize    < (sizeof(effect_param_t) + sizeof(int32_t)) ||
+                        pReplyData == NULL || replySize == NULL ||
+                        *replySize != sizeof(int32_t)) {
                     ALOGV("\tLVM_ERROR : Volume_command cmdCode Case: "
                             "EFFECT_CMD_SET_PARAM: ERROR");
                     return -EINVAL;
@@ -3298,7 +3239,7 @@

 
         case EFFECT_CMD_ENABLE:
             ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_ENABLE start");
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
                 ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: EFFECT_CMD_ENABLE: ERROR");
                 return -EINVAL;
             }
@@ -3308,7 +3249,7 @@

 
         case EFFECT_CMD_DISABLE:
             //ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_DISABLE start");
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
                 ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: EFFECT_CMD_DISABLE: ERROR");
                 return -EINVAL;
             }
@@ -3318,6 +3259,11 @@

         case EFFECT_CMD_SET_DEVICE:
         {
             ALOGV("\tEffect_command cmdCode Case: EFFECT_CMD_SET_DEVICE start");
+            if (pCmdData   == NULL){
+                ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: EFFECT_CMD_SET_DEVICE: ERROR");
+                return -EINVAL;
+            }
+
             uint32_t device = *(uint32_t *)pCmdData;
             pContext->pBundledContext->nOutputDevice = (audio_devices_t) device;
 
@@ -3406,8 +3352,8 @@

                 break;
             }
 
-            if (pCmdData == NULL ||
-                cmdSize != 2 * sizeof(uint32_t)) {
+            if (pCmdData == NULL || cmdSize != 2 * sizeof(uint32_t) || pReplyData == NULL ||
+                    replySize == NULL || *replySize < 2*sizeof(int32_t)) {
                 ALOGV("\tLVM_ERROR : Effect_command cmdCode Case: "
                         "EFFECT_CMD_SET_VOLUME: ERROR");
                 return -EINVAL;

```


### `media/libeffects/lvm/wrapper/Reverb/EffectReverb.cpp`

```diff
@@ -190,8 +190,8 @@

 /* Effect Library Interface Implementation */
 
 extern "C" int EffectCreate(const effect_uuid_t *uuid,
-                            int32_t             sessionId,
-                            int32_t             ioId,
+                            int32_t             sessionId __unused,
+                            int32_t             ioId __unused,
                             effect_handle_t  *pHandle){
     int ret;
     int i;
@@ -1915,7 +1915,7 @@

             //ALOGV("\tReverb_command cmdCode Case: "
             //        "EFFECT_CMD_INIT start");
 
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)){
                 ALOGV("\tLVM_ERROR : Reverb_command cmdCode Case: "
                         "EFFECT_CMD_INIT: ERROR");
                 return -EINVAL;
@@ -1926,10 +1926,8 @@

         case EFFECT_CMD_SET_CONFIG:
             //ALOGV("\tReverb_command cmdCode Case: "
             //        "EFFECT_CMD_SET_CONFIG start");
-            if (pCmdData == NULL ||
-                cmdSize != sizeof(effect_config_t) ||
-                pReplyData == NULL ||
-                *replySize != sizeof(int)) {
+            if (pCmdData == NULL || cmdSize != sizeof(effect_config_t) ||
+                    pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
                 ALOGV("\tLVM_ERROR : Reverb_command cmdCode Case: "
                         "EFFECT_CMD_SET_CONFIG: ERROR");
                 return -EINVAL;
@@ -1939,8 +1937,7 @@

             break;
 
         case EFFECT_CMD_GET_CONFIG:
-            if (pReplyData == NULL ||
-                *replySize != sizeof(effect_config_t)) {
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(effect_config_t)) {
                 ALOGV("\tLVM_ERROR : Reverb_command cmdCode Case: "
                         "EFFECT_CMD_GET_CONFIG: ERROR");
                 return -EINVAL;
@@ -1958,15 +1955,16 @@

         case EFFECT_CMD_GET_PARAM:{
             //ALOGV("\tReverb_command cmdCode Case: "
             //        "EFFECT_CMD_GET_PARAM start");
-            if (pCmdData == NULL ||
-                    cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)) ||
-                    pReplyData == NULL ||
-                    *replySize < (sizeof(effect_param_t) + sizeof(int32_t))){
+            effect_param_t *p = (effect_param_t *)pCmdData;
+
+            if (pCmdData == NULL || cmdSize < sizeof(effect_param_t) ||
+                    cmdSize < (sizeof(effect_param_t) + p->psize) ||
+                    pReplyData == NULL || replySize == NULL ||
+                    *replySize < (sizeof(effect_param_t) + p->psize)) {
                 ALOGV("\tLVM_ERROR : Reverb_command cmdCode Case: "
                         "EFFECT_CMD_GET_PARAM: ERROR");
                 return -EINVAL;
             }
-            effect_param_t *p = (effect_param_t *)pCmdData;
 
             memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
 
@@ -1997,8 +1995,8 @@

             //        *replySize,
             //        *(int16_t *)((char *)pCmdData + sizeof(effect_param_t) + sizeof(int32_t)));
 
-            if (pCmdData == NULL || (cmdSize < (sizeof(effect_param_t) + sizeof(int32_t)))
-                    || pReplyData == NULL || *replySize != sizeof(int32_t)) {
+            if (pCmdData == NULL || (cmdSize < (sizeof(effect_param_t) + sizeof(int32_t))) ||
+                    pReplyData == NULL ||  replySize == NULL || *replySize != sizeof(int32_t)) {
                 ALOGV("\tLVM_ERROR : Reverb_command cmdCode Case: "
                         "EFFECT_CMD_SET_PARAM: ERROR");
                 return -EINVAL;

```


### `media/libeffects/preprocessing/PreProcessing.cpp`

```diff
@@ -575,16 +575,18 @@

     return 0;
 }
 
-int NsGetParameter(preproc_effect_t  *effect,
-                   void              *pParam,
-                   uint32_t          *pValueSize,
-                   void              *pValue)
+int NsGetParameter(preproc_effect_t  *effect __unused,
+                   void              *pParam __unused,
+                   uint32_t          *pValueSize __unused,
+                   void              *pValue __unused)
 {
     int status = 0;
     return status;
 }
 
-int NsSetParameter (preproc_effect_t *effect, void *pParam, void *pValue)
+int NsSetParameter (preproc_effect_t *effect __unused,
+                    void *pParam __unused,
+                    void *pValue __unused)
 {
     int status = 0;
     return status;
@@ -1434,16 +1436,17 @@

             }
             break;
 
-        case EFFECT_CMD_GET_PARAM:{
-            if (pCmdData == NULL ||
-                    cmdSize < (int)sizeof(effect_param_t) ||
-                    pReplyData == NULL ||
-                    *replySize < (int)sizeof(effect_param_t)){
+        case EFFECT_CMD_GET_PARAM: {
+            effect_param_t *p = (effect_param_t *)pCmdData;
+
+            if (pCmdData == NULL || cmdSize < sizeof(effect_param_t) ||
+                    cmdSize < (sizeof(effect_param_t) + p->psize) ||
+                    pReplyData == NULL || replySize == NULL ||
+                    *replySize < (sizeof(effect_param_t) + p->psize)){
                 ALOGV("PreProcessingFx_Command cmdCode Case: "
                         "EFFECT_CMD_GET_PARAM: ERROR");
                 return -EINVAL;
             }
-            effect_param_t *p = (effect_param_t *)pCmdData;
 
             memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);
 
@@ -1461,8 +1464,8 @@

 
         case EFFECT_CMD_SET_PARAM:{
             if (pCmdData == NULL||
-                    cmdSize < (int)sizeof(effect_param_t) ||
-                    pReplyData == NULL ||
+                    cmdSize < sizeof(effect_param_t) ||
+                    pReplyData == NULL || replySize == NULL ||
                     *replySize != sizeof(int32_t)){
                 ALOGV("PreProcessingFx_Command cmdCode Case: "
                         "EFFECT_CMD_SET_PARAM: ERROR");
@@ -1483,7 +1486,7 @@

         } break;
 
         case EFFECT_CMD_ENABLE:
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)){
                 ALOGV("PreProcessingFx_Command cmdCode Case: EFFECT_CMD_ENABLE: ERROR");
                 return -EINVAL;
             }
@@ -1491,7 +1494,7 @@

             break;
 
         case EFFECT_CMD_DISABLE:
-            if (pReplyData == NULL || *replySize != sizeof(int)){
+            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)){
                 ALOGV("PreProcessingFx_Command cmdCode Case: EFFECT_CMD_DISABLE: ERROR");
                 return -EINVAL;
             }
@@ -1711,7 +1714,7 @@

 
 int PreProcessingFx_ProcessReverse(effect_handle_t     self,
                                    audio_buffer_t    *inBuffer,
-                                   audio_buffer_t    *outBuffer)
+                                   audio_buffer_t    *outBuffer __unused)
 {
     preproc_effect_t * effect = (preproc_effect_t *)self;
     int    status = 0;

```


### `media/libeffects/visualizer/EffectVisualizer.cpp`

```diff
@@ -424,21 +424,21 @@

 
     switch (cmdCode) {
     case EFFECT_CMD_INIT:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = Visualizer_init(pContext);
         break;
     case EFFECT_CMD_SET_CONFIG:
         if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
-                || pReplyData == NULL || *replySize != sizeof(int)) {
+                || pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         *(int *) pReplyData = Visualizer_setConfig(pContext,
                 (effect_config_t *) pCmdData);
         break;
     case EFFECT_CMD_GET_CONFIG:
-        if (pReplyData == NULL ||
+        if (pReplyData == NULL || replySize == NULL ||
             *replySize != sizeof(effect_config_t)) {
             return -EINVAL;
         }
@@ -448,7 +448,7 @@

         Visualizer_reset(pContext);
         break;
     case EFFECT_CMD_ENABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pContext->mState != VISUALIZER_STATE_INITIALIZED) {
@@ -459,7 +459,7 @@

         *(int *)pReplyData = 0;
         break;
     case EFFECT_CMD_DISABLE:
-        if (pReplyData == NULL || *replySize != sizeof(int)) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
             return -EINVAL;
         }
         if (pContext->mState != VISUALIZER_STATE_ACTIVE) {
@@ -472,7 +472,7 @@

     case EFFECT_CMD_GET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL ||
+            pReplyData == NULL || replySize == NULL ||
             *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
             return -EINVAL;
         }
@@ -510,7 +510,7 @@

     case EFFECT_CMD_SET_PARAM: {
         if (pCmdData == NULL ||
             cmdSize != (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint32_t)) ||
-            pReplyData == NULL || *replySize != sizeof(int32_t)) {
+            pReplyData == NULL || replySize == NULL || *replySize != sizeof(int32_t)) {
             return -EINVAL;
         }
         *(int32_t *)pReplyData = 0;
@@ -548,7 +548,7 @@

 
     case VISUALIZER_CMD_CAPTURE: {
         uint32_t captureSize = pContext->mCaptureSize;
-        if (pReplyData == NULL || *replySize != captureSize) {
+        if (pReplyData == NULL || replySize == NULL || *replySize != captureSize) {
             ALOGV("VISUALIZER_CMD_CAPTURE() error *replySize %" PRIu32 " captureSize %" PRIu32,
                     *replySize, captureSize);
             return -EINVAL;

```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
