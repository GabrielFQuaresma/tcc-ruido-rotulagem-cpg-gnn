# Pacote de anotacao — caso 46

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

# Evidencia do caso 46

## Identificacao

- projeto: linux
- CVE: CVE-2013-1860
- CWE atribuida pelo BigVul: CWE-119
- commit: `c0f5ecee4e741667b2493c742b60b6218d40b3aa`
- URL do commit: https://github.com/torvalds/linux/commit/c0f5ecee4e741667b2493c742b60b6218d40b3aa
- arquivo da funcao marcada: `drivers/usb/class/cdc-wdm.c`

## Mensagem do commit

> USB: cdc-wdm: fix buffer overflow
> 
> The buffer for responses must not overflow.
> If this would happen, set a flag, drop the data and return
> an error after user space has read all remaining data.
> 
> Signed-off-by: Oliver Neukum <oliver@neukum.org>
> CC: stable@kernel.org
> Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Resumo da CVE

> Heap-based buffer overflow in the wdm_in_callback function in drivers/usb/class/cdc-wdm.c in the Linux kernel before 3.8.4 allows physically proximate attackers to cause a denial of service (system crash) or possibly execute arbitrary code via a crafted cdc-wdm USB device.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -2,6 +2,7 @@
  {
  	struct wdm_device *desc = urb->context;
  	int status = urb->status;
+	int length = urb->actual_length;
  
  	spin_lock(&desc->iuspin);
  	clear_bit(WDM_RESPONDING, &desc->flags);
@@ -32,9 +33,17 @@
  	}
  
  	desc->rerr = status;
-	desc->reslength = urb->actual_length;
-	memmove(desc->ubuf + desc->length, desc->inbuf, desc->reslength);
-	desc->length += desc->reslength;
+	if (length + desc->length > desc->wMaxCommand) {
+		/* The buffer would overflow */
+		set_bit(WDM_OVERFLOW, &desc->flags);
+	} else {
+		/* we may already be in overflow */
+		if (!test_bit(WDM_OVERFLOW, &desc->flags)) {
+			memmove(desc->ubuf + desc->length, desc->inbuf, length);
+			desc->length += length;
+			desc->reslength = length;
+		}
+	}
  skip_error:
  	wake_up(&desc->wait);
  
```

## Corpo completo da funcao antes da correcao

```c
static void wdm_in_callback(struct urb *urb)
 {
 	struct wdm_device *desc = urb->context;
 	int status = urb->status;
 
 	spin_lock(&desc->iuspin);
 	clear_bit(WDM_RESPONDING, &desc->flags);

	if (status) {
		switch (status) {
		case -ENOENT:
			dev_dbg(&desc->intf->dev,
				"nonzero urb status received: -ENOENT");
			goto skip_error;
		case -ECONNRESET:
			dev_dbg(&desc->intf->dev,
				"nonzero urb status received: -ECONNRESET");
			goto skip_error;
		case -ESHUTDOWN:
			dev_dbg(&desc->intf->dev,
				"nonzero urb status received: -ESHUTDOWN");
			goto skip_error;
		case -EPIPE:
			dev_err(&desc->intf->dev,
				"nonzero urb status received: -EPIPE\n");
			break;
		default:
			dev_err(&desc->intf->dev,
				"Unexpected error %d\n", status);
			break;
		}
 	}
 
 	desc->rerr = status;
	desc->reslength = urb->actual_length;
	memmove(desc->ubuf + desc->length, desc->inbuf, desc->reslength);
	desc->length += desc->reslength;
 skip_error:
 	wake_up(&desc->wait);
 
	set_bit(WDM_READ, &desc->flags);
	spin_unlock(&desc->iuspin);
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `drivers/usb/class/cdc-wdm.c` **(funcao marcada esta aqui)** | modified | 20 | 3 |


### `drivers/usb/class/cdc-wdm.c`

```diff
@@ -56,6 +56,7 @@ MODULE_DEVICE_TABLE (usb, wdm_ids);
 #define WDM_RESPONDING		7
 #define WDM_SUSPENDING		8
 #define WDM_RESETTING		9
+#define WDM_OVERFLOW		10
 
 #define WDM_MAX			16
 
@@ -155,6 +156,7 @@ static void wdm_in_callback(struct urb *urb)
 {
 	struct wdm_device *desc = urb->context;
 	int status = urb->status;
+	int length = urb->actual_length;
 
 	spin_lock(&desc->iuspin);
 	clear_bit(WDM_RESPONDING, &desc->flags);
@@ -185,9 +187,17 @@ static void wdm_in_callback(struct urb *urb)
 	}
 
 	desc->rerr = status;
-	desc->reslength = urb->actual_length;
-	memmove(desc->ubuf + desc->length, desc->inbuf, desc->reslength);
-	desc->length += desc->reslength;
+	if (length + desc->length > desc->wMaxCommand) {
+		/* The buffer would overflow */
+		set_bit(WDM_OVERFLOW, &desc->flags);
+	} else {
+		/* we may already be in overflow */
+		if (!test_bit(WDM_OVERFLOW, &desc->flags)) {
+			memmove(desc->ubuf + desc->length, desc->inbuf, length);
+			desc->length += length;
+			desc->reslength = length;
+		}
+	}
 skip_error:
 	wake_up(&desc->wait);
 
@@ -435,6 +445,11 @@ static ssize_t wdm_read
 			rv = -ENODEV;
 			goto err;
 		}
+		if (test_bit(WDM_OVERFLOW, &desc->flags)) {
+			clear_bit(WDM_OVERFLOW, &desc->flags);
+			rv = -ENOBUFS;
+			goto err;
+		}
 		i++;
 		if (file->f_flags & O_NONBLOCK) {
 			if (!test_bit(WDM_READ, &desc->flags)) {
@@ -478,6 +493,7 @@ static ssize_t wdm_read
 			spin_unlock_irq(&desc->iuspin);
 			goto retry;
 		}
+
 		if (!desc->reslength) { /* zero length read */
 			dev_dbg(&desc->intf->dev, "%s: zero length - clearing WDM_READ\n", __func__);
 			clear_bit(WDM_READ, &desc->flags);
@@ -1004,6 +1020,7 @@ static int wdm_post_reset(struct usb_interface *intf)
 	struct wdm_device *desc = wdm_find_device(intf);
 	int rv;
 
+	clear_bit(WDM_OVERFLOW, &desc->flags);
 	clear_bit(WDM_RESETTING, &desc->flags);
 	rv = recover_from_urb_loss(desc);
 	mutex_unlock(&desc->wlock);
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
