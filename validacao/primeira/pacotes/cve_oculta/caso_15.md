# Pacote de anotacao — caso 15

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

# Evidencia do caso 15

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-787
- arquivo da funcao marcada: `_ausente_`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -23,6 +23,16 @@
  	return NULL;
      }
  
+    if (rep.length > INT_MAX >> 2 || rep.length < (OutputInfoExtra >> 2))
+    {
+        if (rep.length > (OutputInfoExtra >> 2))
+	    _XEatDataWords (dpy, rep.length - (OutputInfoExtra >> 2));
+	else
+	    _XEatDataWords (dpy, rep.length);
+	UnlockDisplay (dpy);
+	SyncHandle ();
+	return NULL;
+    }
      nbytes = ((long) (rep.length) << 2) - OutputInfoExtra;
  
      nbytesRead = (long) (rep.nCrtcs * 4 +
```

## Corpo completo da funcao antes da correcao

```c
XRRGetOutputInfo (Display *dpy, XRRScreenResources *resources, RROutput output)
{
    XExtDisplayInfo		*info = XRRFindDisplay(dpy);
    xRRGetOutputInfoReply	rep;
    xRRGetOutputInfoReq		*req;
    int				nbytes, nbytesRead, rbytes;
    XRROutputInfo		*xoi;

    RRCheckExtension (dpy, info, NULL);

    LockDisplay (dpy);
    GetReq (RRGetOutputInfo, req);
    req->reqType = info->codes->major_opcode;
    req->randrReqType = X_RRGetOutputInfo;
    req->output = output;
    req->configTimestamp = resources->configTimestamp;

    if (!_XReply (dpy, (xReply *) &rep, OutputInfoExtra >> 2, xFalse))
    {
	UnlockDisplay (dpy);
	SyncHandle ();
	return NULL;
 	return NULL;
     }
 
     nbytes = ((long) (rep.length) << 2) - OutputInfoExtra;
 
     nbytesRead = (long) (rep.nCrtcs * 4 +
	      rep.nCrtcs * sizeof (RRCrtc) +
	      rep.nModes * sizeof (RRMode) +
	      rep.nClones * sizeof (RROutput) +
	      rep.nameLength + 1);	    /* '\0' terminate name */

    xoi = (XRROutputInfo *) Xmalloc(rbytes);
    if (xoi == NULL) {
	_XEatDataWords (dpy, rep.length - (OutputInfoExtra >> 2));
	UnlockDisplay (dpy);
	SyncHandle ();
	return NULL;
    }

    xoi->timestamp = rep.timestamp;
    xoi->crtc = rep.crtc;
    xoi->mm_width = rep.mmWidth;
    xoi->mm_height = rep.mmHeight;
    xoi->connection = rep.connection;
    xoi->subpixel_order = rep.subpixelOrder;
    xoi->ncrtc = rep.nCrtcs;
    xoi->crtcs = (RRCrtc *) (xoi + 1);
    xoi->nmode = rep.nModes;
    xoi->npreferred = rep.nPreferred;
    xoi->modes = (RRMode *) (xoi->crtcs + rep.nCrtcs);
    xoi->nclone = rep.nClones;
    xoi->clones = (RROutput *) (xoi->modes + rep.nModes);
    xoi->name = (char *) (xoi->clones + rep.nClones);

    _XRead32 (dpy, (long *) xoi->crtcs, rep.nCrtcs << 2);
    _XRead32 (dpy, (long *) xoi->modes, rep.nModes << 2);
    _XRead32 (dpy, (long *) xoi->clones, rep.nClones << 2);

    /*
     * Read name and '\0' terminate
     */
    _XReadPad (dpy, xoi->name, rep.nameLength);
    xoi->name[rep.nameLength] = '\0';
    xoi->nameLen = rep.nameLength;

    /*
     * Skip any extra data
     */
    if (nbytes > nbytesRead)
	_XEatData (dpy, (unsigned long) (nbytes - nbytesRead));

    UnlockDisplay (dpy);
    SyncHandle ();
    return (XRROutputInfo *) xoi;
}

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
