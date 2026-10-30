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

- projeto: openjpeg
- CVE: CVE-2016-7163
- CWE atribuida pelo BigVul: CWE-125
- commit: `c16bc057ba3f125051c9966cf1f5b68a05681de4`
- URL do commit: https://github.com/uclouvain/openjpeg/commit/c16bc057ba3f125051c9966cf1f5b68a05681de4
- arquivo da funcao marcada: `src/lib/openjp2/pi.c`

## Mensagem do commit

> Fix an integer overflow issue (#809)
> 
> Prevent an integer overflow issue in function opj_pi_create_decode of
> pi.c.

## Resumo da CVE

> Integer overflow in the opj_pi_create_decode function in pi.c in OpenJPEG allows remote attackers to execute arbitrary code via a crafted JP2 file, which triggers an out-of-bounds read or write.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -83,7 +83,13 @@
  	l_current_pi = l_pi;
  
  	/* memory allocation for include */
-	l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
+	/* prevent an integer overflow issue */
+	l_current_pi->include = 00;
+	if (l_step_l <= (SIZE_MAX / (l_tcp->numlayers + 1U)))
+	{
+		l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
+	}
+
  	if
  		(!l_current_pi->include)
  	{
```

## Corpo completo da funcao antes da correcao

```c
opj_pi_iterator_t *opj_pi_create_decode(opj_image_t *p_image,
										opj_cp_t *p_cp,
										OPJ_UINT32 p_tile_no)
{
	/* loop */
	OPJ_UINT32 pino;
	OPJ_UINT32 compno, resno;

	/* to store w, h, dx and dy fro all components and resolutions */
	OPJ_UINT32 * l_tmp_data;
	OPJ_UINT32 ** l_tmp_ptr;

	/* encoding prameters to set */
	OPJ_UINT32 l_max_res;
	OPJ_UINT32 l_max_prec;
	OPJ_INT32 l_tx0,l_tx1,l_ty0,l_ty1;
	OPJ_UINT32 l_dx_min,l_dy_min;
	OPJ_UINT32 l_bound;
	OPJ_UINT32 l_step_p , l_step_c , l_step_r , l_step_l ;
	OPJ_UINT32 l_data_stride;

	/* pointers */
	opj_pi_iterator_t *l_pi = 00;
	opj_tcp_t *l_tcp = 00;
	const opj_tccp_t *l_tccp = 00;
	opj_pi_comp_t *l_current_comp = 00;
	opj_image_comp_t * l_img_comp = 00;
	opj_pi_iterator_t * l_current_pi = 00;
	OPJ_UINT32 * l_encoding_value_ptr = 00;

	/* preconditions in debug */
	assert(p_cp != 00);
	assert(p_image != 00);
	assert(p_tile_no < p_cp->tw * p_cp->th);

	/* initializations */
	l_tcp = &p_cp->tcps[p_tile_no];
	l_bound = l_tcp->numpocs+1;

	l_data_stride = 4 * OPJ_J2K_MAXRLVLS;
	l_tmp_data = (OPJ_UINT32*)opj_malloc(
		l_data_stride * p_image->numcomps * sizeof(OPJ_UINT32));
	if
		(! l_tmp_data)
	{
		return 00;
	}
	l_tmp_ptr = (OPJ_UINT32**)opj_malloc(
		p_image->numcomps * sizeof(OPJ_UINT32 *));
	if
		(! l_tmp_ptr)
	{
		opj_free(l_tmp_data);
		return 00;
	}

	/* memory allocation for pi */
	l_pi = opj_pi_create(p_image, p_cp, p_tile_no);
	if (!l_pi) {
		opj_free(l_tmp_data);
		opj_free(l_tmp_ptr);
		return 00;
	}

	l_encoding_value_ptr = l_tmp_data;
	/* update pointer array */
	for
		(compno = 0; compno < p_image->numcomps; ++compno)
	{
		l_tmp_ptr[compno] = l_encoding_value_ptr;
		l_encoding_value_ptr += l_data_stride;
	}
	/* get encoding parameters */
	opj_get_all_encoding_parameters(p_image,p_cp,p_tile_no,&l_tx0,&l_tx1,&l_ty0,&l_ty1,&l_dx_min,&l_dy_min,&l_max_prec,&l_max_res,l_tmp_ptr);

	/* step calculations */
	l_step_p = 1;
	l_step_c = l_max_prec * l_step_p;
	l_step_r = p_image->numcomps * l_step_c;
	l_step_l = l_max_res * l_step_r;

	/* set values for first packet iterator */
 	l_current_pi = l_pi;
 
 	/* memory allocation for include */
	l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
 	if
 		(!l_current_pi->include)
 	{
		opj_free(l_tmp_data);
		opj_free(l_tmp_ptr);
		opj_pi_destroy(l_pi, l_bound);
		return 00;
	}

	/* special treatment for the first packet iterator */
	l_current_comp = l_current_pi->comps;
	l_img_comp = p_image->comps;
	l_tccp = l_tcp->tccps;

	l_current_pi->tx0 = l_tx0;
	l_current_pi->ty0 = l_ty0;
	l_current_pi->tx1 = l_tx1;
	l_current_pi->ty1 = l_ty1;

	/*l_current_pi->dx = l_img_comp->dx;*/
	/*l_current_pi->dy = l_img_comp->dy;*/

	l_current_pi->step_p = l_step_p;
	l_current_pi->step_c = l_step_c;
	l_current_pi->step_r = l_step_r;
	l_current_pi->step_l = l_step_l;

	/* allocation for components and number of components has already been calculated by opj_pi_create */
	for
		(compno = 0; compno < l_current_pi->numcomps; ++compno)
	{
		opj_pi_resolution_t *l_res = l_current_comp->resolutions;
		l_encoding_value_ptr = l_tmp_ptr[compno];

		l_current_comp->dx = l_img_comp->dx;
		l_current_comp->dy = l_img_comp->dy;
		/* resolutions have already been initialized */
		for
			(resno = 0; resno < l_current_comp->numresolutions; resno++)
		{
			l_res->pdx = *(l_encoding_value_ptr++);
			l_res->pdy = *(l_encoding_value_ptr++);
			l_res->pw =  *(l_encoding_value_ptr++);
			l_res->ph =  *(l_encoding_value_ptr++);
			++l_res;
		}
		++l_current_comp;
		++l_img_comp;
		++l_tccp;
	}
	++l_current_pi;

	for (pino = 1 ; pino<l_bound ; ++pino )
	{
		l_current_comp = l_current_pi->comps;
		l_img_comp = p_image->comps;
		l_tccp = l_tcp->tccps;

		l_current_pi->tx0 = l_tx0;
		l_current_pi->ty0 = l_ty0;
		l_current_pi->tx1 = l_tx1;
		l_current_pi->ty1 = l_ty1;
		/*l_current_pi->dx = l_dx_min;*/
		/*l_current_pi->dy = l_dy_min;*/
		l_current_pi->step_p = l_step_p;
		l_current_pi->step_c = l_step_c;
		l_current_pi->step_r = l_step_r;
		l_current_pi->step_l = l_step_l;

		/* allocation for components and number of components has already been calculated by opj_pi_create */
		for
			(compno = 0; compno < l_current_pi->numcomps; ++compno)
		{
			opj_pi_resolution_t *l_res = l_current_comp->resolutions;
			l_encoding_value_ptr = l_tmp_ptr[compno];

			l_current_comp->dx = l_img_comp->dx;
			l_current_comp->dy = l_img_comp->dy;
			/* resolutions have already been initialized */
			for
				(resno = 0; resno < l_current_comp->numresolutions; resno++)
			{
				l_res->pdx = *(l_encoding_value_ptr++);
				l_res->pdy = *(l_encoding_value_ptr++);
				l_res->pw =  *(l_encoding_value_ptr++);
				l_res->ph =  *(l_encoding_value_ptr++);
				++l_res;
			}
			++l_current_comp;
			++l_img_comp;
			++l_tccp;
		}
		/* special treatment*/
		l_current_pi->include = (l_current_pi-1)->include;
		++l_current_pi;
	}
	opj_free(l_tmp_data);
	l_tmp_data = 00;
	opj_free(l_tmp_ptr);
	l_tmp_ptr = 00;
	if
		(l_tcp->POC)
	{
		opj_pi_update_decode_poc (l_pi,l_tcp,l_max_prec,l_max_res);
	}
	else
	{
		opj_pi_update_decode_not_poc(l_pi,l_tcp,l_max_prec,l_max_res);
	}
	return l_pi;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/lib/openjp2/pi.c` **(funcao marcada esta aqui)** | modified | 7 | 1 |


### `src/lib/openjp2/pi.c`

```diff
@@ -1237,7 +1237,13 @@ opj_pi_iterator_t *opj_pi_create_decode(opj_image_t *p_image,
 	l_current_pi = l_pi;
 
 	/* memory allocation for include */
-	l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
+	/* prevent an integer overflow issue */
+	l_current_pi->include = 00;
+	if (l_step_l <= (SIZE_MAX / (l_tcp->numlayers + 1U)))
+	{
+		l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
+	}
+
 	if
 		(!l_current_pi->include)
 	{
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
