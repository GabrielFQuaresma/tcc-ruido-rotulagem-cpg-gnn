# Pacote de anotacao — caso 40

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

# Evidencia do caso 40

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `drivers/net/mlx4/port.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -19,6 +19,12 @@
  			goto out;
  		}
  	}
+
+	if (free < 0) {
+		err = -ENOMEM;
+		goto out;
+	}
+
  	mlx4_dbg(dev, "Free MAC index is %d\n", free);
  
  	if (table->total == table->max) {
```

## Corpo completo da funcao antes da correcao

```c
int mlx4_register_mac(struct mlx4_dev *dev, u8 port, u64 mac, int *index)
{
	struct mlx4_mac_table *table = &mlx4_priv(dev)->port[port].mac_table;
	int i, err = 0;
	int free = -1;

	mlx4_dbg(dev, "Registering MAC: 0x%llx\n", (unsigned long long) mac);
	mutex_lock(&table->mutex);
	for (i = 0; i < MLX4_MAX_MAC_NUM - 1; i++) {
		if (free < 0 && !table->refs[i]) {
			free = i;
			continue;
		}

		if (mac == (MLX4_MAC_MASK & be64_to_cpu(table->entries[i]))) {
			/* MAC already registered, increase refernce count */
			*index = i;
			++table->refs[i];
 			goto out;
 		}
 	}
 	mlx4_dbg(dev, "Free MAC index is %d\n", free);
 
 	if (table->total == table->max) {
		/* No free mac entries */
		err = -ENOSPC;
		goto out;
	}

	/* Register new MAC */
	table->refs[free] = 1;
	table->entries[free] = cpu_to_be64(mac | MLX4_MAC_VALID);

	err = mlx4_set_port_mac_table(dev, port, table->entries);
	if (unlikely(err)) {
		mlx4_err(dev, "Failed adding MAC: 0x%llx\n", (unsigned long long) mac);
		table->refs[free] = 0;
		table->entries[free] = 0;
		goto out;
	}

	*index = free;
	++table->total;
out:
	mutex_unlock(&table->mutex);
	return err;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `drivers/net/mlx4/port.c` **(funcao marcada esta aqui)** | modified | 11 | 0 |


### `drivers/net/mlx4/port.c`

```diff
@@ -111,6 +111,12 @@ int mlx4_register_mac(struct mlx4_dev *dev, u8 port, u64 mac, int *index)
 			goto out;
 		}
 	}
+
+	if (free < 0) {
+		err = -ENOMEM;
+		goto out;
+	}
+
 	mlx4_dbg(dev, "Free MAC index is %d\n", free);
 
 	if (table->total == table->max) {
@@ -205,6 +211,11 @@ int mlx4_register_vlan(struct mlx4_dev *dev, u8 port, u16 vlan, int *index)
 		}
 	}
 
+	if (free < 0) {
+		err = -ENOMEM;
+		goto out;
+	}
+
 	if (table->total == table->max) {
 		/* No free vlan entries */
 		err = -ENOSPC;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
