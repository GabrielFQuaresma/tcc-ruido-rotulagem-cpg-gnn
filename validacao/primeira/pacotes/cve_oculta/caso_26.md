# Pacote de anotacao — caso 26

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

# Evidencia do caso 26

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `drivers/net/ethernet/hisilicon/hns/hns_dsaf_gmac.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  static int hns_gmac_get_sset_count(int stringset)
  {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
  		return ARRAY_SIZE(g_gmac_stats_string);
  
  	return 0;
```

## Corpo completo da funcao antes da correcao

```c
 static int hns_gmac_get_sset_count(int stringset)
 {
	if (stringset == ETH_SS_STATS)
 		return ARRAY_SIZE(g_gmac_stats_string);
 
 	return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **4**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `drivers/net/ethernet/hisilicon/hns/hns_dsaf_gmac.c` **(funcao marcada esta aqui)** | modified | 1 | 1 |
| `drivers/net/ethernet/hisilicon/hns/hns_dsaf_ppe.c` | modified | 1 | 1 |
| `drivers/net/ethernet/hisilicon/hns/hns_dsaf_rcb.c` | modified | 1 | 1 |
| `drivers/net/ethernet/hisilicon/hns/hns_dsaf_xgmac.c` | modified | 1 | 1 |


### `drivers/net/ethernet/hisilicon/hns/hns_dsaf_gmac.c`

```diff
@@ -666,7 +666,7 @@ static void hns_gmac_get_strings(u32 stringset, u8 *data)
 
 static int hns_gmac_get_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return ARRAY_SIZE(g_gmac_stats_string);
 
 	return 0;
```


### `drivers/net/ethernet/hisilicon/hns/hns_dsaf_ppe.c`

```diff
@@ -422,7 +422,7 @@ void hns_ppe_update_stats(struct hns_ppe_cb *ppe_cb)
 
 int hns_ppe_get_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return ETH_PPE_STATIC_NUM;
 	return 0;
 }
```


### `drivers/net/ethernet/hisilicon/hns/hns_dsaf_rcb.c`

```diff
@@ -876,7 +876,7 @@ void hns_rcb_get_stats(struct hnae_queue *queue, u64 *data)
  */
 int hns_rcb_get_ring_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return HNS_RING_STATIC_REG_NUM;
 
 	return 0;
```


### `drivers/net/ethernet/hisilicon/hns/hns_dsaf_xgmac.c`

```diff
@@ -781,7 +781,7 @@ static void hns_xgmac_get_strings(u32 stringset, u8 *data)
  */
 static int hns_xgmac_get_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return ARRAY_SIZE(g_xgmac_stats_string);
 
 	return 0;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
