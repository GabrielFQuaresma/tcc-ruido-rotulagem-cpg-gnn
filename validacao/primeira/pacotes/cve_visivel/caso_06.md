# Pacote de anotacao — caso 06

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

# Evidencia do caso 06

## Identificacao

- projeto: linux
- CVE: CVE-2016-4998
- CWE atribuida pelo BigVul: CWE-119
- commit: `6e94e0cfb0887e4013b3b930fa6ab1fe6bb6ba91`
- URL do commit: https://github.com/torvalds/linux/commit/6e94e0cfb0887e4013b3b930fa6ab1fe6bb6ba91
- arquivo da funcao marcada: `net/ipv4/netfilter/ip_tables.c`

## Mensagem do commit

> netfilter: x_tables: make sure e->next_offset covers remaining blob size
> 
> Otherwise this function may read data beyond the ruleset blob.
> 
> Signed-off-by: Florian Westphal <fw@strlen.de>
> Signed-off-by: Pablo Neira Ayuso <pablo@netfilter.org>

## Resumo da CVE

> The IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel before 4.6 allows local users to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from kernel heap memory by leveraging in-container root access to provide a crafted offset value that leads to crossing a ruleset blob boundary.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -10,7 +10,8 @@
  	int err;
  
  	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
  		duprintf("Bad offset %p\n", e);
  		return -EINVAL;
  	}
```

## Corpo completo da funcao antes da correcao

```c
check_entry_size_and_hooks(struct ipt_entry *e,
			   struct xt_table_info *newinfo,
			   const unsigned char *base,
			   const unsigned char *limit,
			   const unsigned int *hook_entries,
			   const unsigned int *underflows,
			   unsigned int valid_hooks)
{
	unsigned int h;
 	int err;
 
 	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit) {
 		duprintf("Bad offset %p\n", e);
 		return -EINVAL;
 	}

	if (e->next_offset
	    < sizeof(struct ipt_entry) + sizeof(struct xt_entry_target)) {
		duprintf("checking: element %p size %u\n",
			 e, e->next_offset);
		return -EINVAL;
	}

	err = check_entry(e);
	if (err)
		return err;

	/* Check hooks & underflows */
	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if (!(valid_hooks & (1 << h)))
			continue;
		if ((unsigned char *)e - base == hook_entries[h])
			newinfo->hook_entry[h] = hook_entries[h];
		if ((unsigned char *)e - base == underflows[h]) {
			if (!check_underflow(e)) {
				pr_err("Underflows must be unconditional and "
				       "use the STANDARD target with "
				       "ACCEPT/DROP\n");
				return -EINVAL;
			}
			newinfo->underflow[h] = underflows[h];
		}
	}

	/* Clear counters and comefrom */
	e->counters = ((struct xt_counters) { 0, 0 });
	e->comefrom = 0;
	return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `net/ipv4/netfilter/arp_tables.c` | modified | 4 | 2 |
| `net/ipv4/netfilter/ip_tables.c` **(funcao marcada esta aqui)** | modified | 4 | 2 |
| `net/ipv6/netfilter/ip6_tables.c` | modified | 4 | 2 |


### `net/ipv4/netfilter/ip_tables.c`

```diff
@@ -738,7 +738,8 @@ check_entry_size_and_hooks(struct ipt_entry *e,
 	int err;
 
 	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p\n", e);
 		return -EINVAL;
 	}
@@ -1492,7 +1493,8 @@ check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
 
 	duprintf("check_compat_entry_size_and_hooks %p\n", e);
 	if ((unsigned long)e % __alignof__(struct compat_ipt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p, limit = %p\n", e, limit);
 		return -EINVAL;
 	}
```


### `net/ipv4/netfilter/arp_tables.c`

```diff
@@ -573,7 +573,8 @@ static inline int check_entry_size_and_hooks(struct arpt_entry *e,
 	int err;
 
 	if ((unsigned long)e % __alignof__(struct arpt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct arpt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct arpt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p\n", e);
 		return -EINVAL;
 	}
@@ -1232,7 +1233,8 @@ check_compat_entry_size_and_hooks(struct compat_arpt_entry *e,
 
 	duprintf("check_compat_entry_size_and_hooks %p\n", e);
 	if ((unsigned long)e % __alignof__(struct compat_arpt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct compat_arpt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct compat_arpt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p, limit = %p\n", e, limit);
 		return -EINVAL;
 	}
```


### `net/ipv6/netfilter/ip6_tables.c`

```diff
@@ -750,7 +750,8 @@ check_entry_size_and_hooks(struct ip6t_entry *e,
 	int err;
 
 	if ((unsigned long)e % __alignof__(struct ip6t_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct ip6t_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct ip6t_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p\n", e);
 		return -EINVAL;
 	}
@@ -1504,7 +1505,8 @@ check_compat_entry_size_and_hooks(struct compat_ip6t_entry *e,
 
 	duprintf("check_compat_entry_size_and_hooks %p\n", e);
 	if ((unsigned long)e % __alignof__(struct compat_ip6t_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct compat_ip6t_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct compat_ip6t_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
 		duprintf("Bad offset %p, limit = %p\n", e, limit);
 		return -EINVAL;
 	}
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
