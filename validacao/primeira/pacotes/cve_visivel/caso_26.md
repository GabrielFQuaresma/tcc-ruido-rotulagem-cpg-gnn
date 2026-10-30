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

- projeto: linux
- CVE: CVE-2017-18222
- CWE atribuida pelo BigVul: CWE-119
- commit: `412b65d15a7f8a93794653968308fc100f2aa87c`
- URL do commit: https://github.com/torvalds/linux/commit/412b65d15a7f8a93794653968308fc100f2aa87c
- arquivo da funcao marcada: `drivers/net/ethernet/hisilicon/hns/hns_dsaf_gmac.c`

## Mensagem do commit

> net: hns: fix ethtool_get_strings overflow in hns driver
> 
> hns_get_sset_count() returns HNS_NET_STATS_CNT and the data space allocated
> is not enough for ethtool_get_strings(), which will cause random memory
> corruption.
> 
> When SLAB and DEBUG_SLAB are both enabled, memory corruptions like the
> the following can be observed without this patch:
> [   43.115200] Slab corruption (Not tainted): Acpi-ParseExt start=ffff801fb0b69030, len=80
> [   43.115206] Redzone: 0x9f911029d006462/0x5f78745f31657070.
> [   43.115208] Last user: [<5f7272655f746b70>](0x5f7272655f746b70)
> [   43.115214] 010: 70 70 65 31 5f 74 78 5f 70 6b 74 00 6b 6b 6b 6b  ppe1_tx_pkt.kkkk
> [   43.115217] 030: 70 70 65 31 5f 74 78 5f 70 6b 74 5f 6f 6b 00 6b  ppe1_tx_pkt_ok.k
> [   43.115218] Next obj: start=ffff801fb0b69098, len=80
> [   43.115220] Redzone: 0x706d655f6f666966/0x9f911029d74e35b.
> [   43.115229] Last user: [<ffff0000084b11b0>](acpi_os_release_object+0x28/0x38)
> [   43.115231] 000: 74 79 00 6b 6b 6b 6b 6b 70 70 65 31 5f 74 78 5f  ty.kkkkkppe1_tx_
> [   43.115232] 010: 70 6b 74 5f 65 72 72 5f 63 73 75 6d 5f 66 61 69  pkt_err_csum_fai
> 
> Signed-off-by: Timmy Li <lixiaoping3@huawei.com>
> Signed-off-by: David S. Miller <davem@davemloft.net>

## Resumo da CVE

> In the Linux kernel before 4.12, Hisilicon Network Subsystem (HNS) does not consider the ETH_SS_PRIV_FLAGS case when retrieving sset_count data, which allows local users to cause a denial of service (buffer overflow and memory corruption) or possibly have unspecified other impact, as demonstrated by incompatibility between hns_get_sset_count and ethtool_get_strings.

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
