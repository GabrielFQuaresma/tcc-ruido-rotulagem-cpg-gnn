# Pacote de anotacao — caso 04

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

# Evidencia do caso 04

## Identificacao

- projeto: libgd
- CVE: CVE-2016-6906
- CWE atribuida pelo BigVul: CWE-125
- commit: `fb0e0cce0b9f25389ab56604c3547351617e1415`
- URL do commit: https://github.com/libgd/libgd/commit/fb0e0cce0b9f25389ab56604c3547351617e1415
- arquivo da funcao marcada: `src/gd_tga.c`

## Mensagem do commit

> Fix OOB reads of the TGA decompression buffer
> 
> It is possible to craft TGA files which will overflow the decompression
> buffer, but not the image's bitmap. Therefore we augment the check for the
> bitmap's overflow with a check for the buffer's overflow.
> 
> This issue had been reported by Ibrahim El-Sayed to security@libgd.org.
> 
> CVE-2016-6906

## Resumo da CVE

> The read_image_tga function in gd_tga.c in the GD Graphics Library (aka libgd) before 2.2.4 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted TGA file, related to the decompression buffer.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -95,7 +95,8 @@
  				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
  				buffer_caret++;
  
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + pixel_block_size > rle_size) {
  					gdFree( decompression_buffer );
  					gdFree( conversion_buffer );
  					return -1;
@@ -111,7 +112,8 @@
  				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
  				buffer_caret++;
  
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + (encoded_pixels * pixel_block_size) > rle_size) {
  					gdFree( decompression_buffer );
  					gdFree( conversion_buffer );
  					return -1;
```

## Corpo completo da funcao antes da correcao

```c
int read_image_tga( gdIOCtx *ctx, oTga *tga )
{
	int pixel_block_size = (tga->bits / 8);
	int image_block_size = (tga->width * tga->height) * pixel_block_size;
	int* decompression_buffer = NULL;
	unsigned char* conversion_buffer = NULL;
	int buffer_caret = 0;
	int bitmap_caret = 0;
	int i = 0;
	int encoded_pixels;
	int rle_size;

	if(overflow2(tga->width, tga->height)) {
		return -1;
	}

	if(overflow2(tga->width * tga->height, pixel_block_size)) {
		return -1;
	}

	if(overflow2(image_block_size, sizeof(int))) {
		return -1;
	}

	/*! \todo Add more image type support.
	 */
	if (tga->imagetype != TGA_TYPE_RGB && tga->imagetype != TGA_TYPE_RGB_RLE)
		return -1;

	/*!	\brief Allocate memmory for image block
	 *  Allocate a chunk of memory for the image block to be passed into.
	 */
	tga->bitmap = (int *) gdMalloc(image_block_size * sizeof(int));
	if (tga->bitmap == NULL)
		return -1;

	switch (tga->imagetype) {
	case TGA_TYPE_RGB:
		/*! \brief Read in uncompressed RGB TGA
		 *  Chunk load the pixel data from an uncompressed RGB type TGA.
		 */
		conversion_buffer = (unsigned char *) gdMalloc(image_block_size * sizeof(unsigned char));
		if (conversion_buffer == NULL) {
			return -1;
		}

		if (gdGetBuf(conversion_buffer, image_block_size, ctx) != image_block_size) {
			gd_error("gd-tga: premature end of image data\n");
			gdFree(conversion_buffer);
			return -1;
		}

		while (buffer_caret < image_block_size) {
			tga->bitmap[buffer_caret] = (int) conversion_buffer[buffer_caret];
			buffer_caret++;
		}

		gdFree(conversion_buffer);
		break;

	case TGA_TYPE_RGB_RLE:
		/*! \brief Read in RLE compressed RGB TGA
		 *  Chunk load the pixel data from an RLE compressed RGB type TGA.
		 */
		decompression_buffer = (int*) gdMalloc(image_block_size * sizeof(int));
		if (decompression_buffer == NULL) {
			return -1;
		}
		conversion_buffer = (unsigned char *) gdMalloc(image_block_size * sizeof(unsigned char));
		if (conversion_buffer == NULL) {
			gd_error("gd-tga: premature end of image data\n");
			gdFree( decompression_buffer );
			return -1;
		}

		rle_size = gdGetBuf(conversion_buffer, image_block_size, ctx);
		if (rle_size <= 0) {
			gdFree(conversion_buffer);
			gdFree(decompression_buffer);
			return -1;
		}

		buffer_caret = 0;

		while( buffer_caret < rle_size) {
			decompression_buffer[buffer_caret] = (int)conversion_buffer[buffer_caret];
			buffer_caret++;
		}

		buffer_caret = 0;

		while( bitmap_caret < image_block_size ) {
			
			if ((decompression_buffer[buffer_caret] & TGA_RLE_FLAG) == TGA_RLE_FLAG) {
 				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
 				buffer_caret++;
 
				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
				}

				for (i = 0; i < encoded_pixels; i++) {
					memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, pixel_block_size * sizeof(int));
					bitmap_caret += pixel_block_size;
				}
				buffer_caret += pixel_block_size;

			} else {
 				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
 				buffer_caret++;
 
				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
				}

				memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, encoded_pixels * pixel_block_size * sizeof(int));
				bitmap_caret += (encoded_pixels * pixel_block_size);
				buffer_caret += (encoded_pixels * pixel_block_size);
			}
		}
		gdFree( decompression_buffer );
		gdFree( conversion_buffer );
		break;
	}

	return 1;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **6**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/gd_tga.c` **(funcao marcada esta aqui)** | modified | 4 | 2 |
| `tests/tga/.gitignore` | modified | 1 | 0 |
| `tests/tga/CMakeLists.txt` | modified | 1 | 0 |
| `tests/tga/Makemodule.am` | modified | 2 | 0 |
| `tests/tga/heap_overflow.c` | added | 51 | 0 |
| `tests/tga/heap_overflow.tga` | added | 0 | 0 |


### `src/gd_tga.c`

```diff
@@ -300,7 +300,8 @@ int read_image_tga( gdIOCtx *ctx, oTga *tga )
 				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
 				buffer_caret++;
 
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + pixel_block_size > rle_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
@@ -316,7 +317,8 @@ int read_image_tga( gdIOCtx *ctx, oTga *tga )
 				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
 				buffer_caret++;
 
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + (encoded_pixels * pixel_block_size) > rle_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
```


### `tests/tga/.gitignore`

```diff
@@ -3,5 +3,6 @@
 /bug00247a
 /bug00248
 /bug00248a
+/heap_overflow
 /tga_null
 /tga_read
```


### `tests/tga/CMakeLists.txt`

```diff
@@ -5,6 +5,7 @@ LIST(APPEND TESTS_FILES
 	bug00247a
 	bug00248
 	bug00248a
+	heap_overflow
 	tga_read
 )
 
```


### `tests/tga/Makemodule.am`

```diff
@@ -4,6 +4,7 @@ libgd_test_programs += \
 	tga/bug00247a \
 	tga/bug00248 \
 	tga/bug00248a \
+	tga/heap_overflow \
 	tga/tga_null \
 	tga/tga_read
 
@@ -14,6 +15,7 @@ EXTRA_DIST += \
 	tga/bug00247a.tga \
 	tga/bug00248.tga \
 	tga/bug00248a.tga \
+	tga/heap_overflow.tga \
 	tga/tga_read_rgb.png \
 	tga/tga_read_rgb.tga \
 	tga/tga_read_rgb_rle.tga
```


### `tests/tga/heap_overflow.c`

```diff
@@ -0,0 +1,51 @@
+/**
+ * Test that the crafted TGA file doesn't trigger OOB reads.
+ */
+
+
+#include "gd.h"
+#include "gdtest.h"
+
+
+static size_t read_test_file(char **buffer, char *basename);
+
+
+int main()
+{
+    gdImagePtr im;
+    char *buffer;
+    size_t size;
+
+    size = read_test_file(&buffer, "heap_overflow.tga");
+    im = gdImageCreateFromTgaPtr(size, (void *) buffer);
+    gdTestAssert(im == NULL);
+    free(buffer);
+
+    return gdNumFailures();
+}
+
+
+static size_t read_test_file(char **buffer, char *basename)
+{
+    char *filename;
+    FILE *fp;
+    size_t exp_size, act_size;
+
+    filename = gdTestFilePath2("tga", basename);
+    fp = fopen(filename, "rb");
+    gdTestAssert(fp != NULL);
+
+	fseek(fp, 0, SEEK_END);
+	exp_size = ftell(fp);
+	fseek(fp, 0, SEEK_SET);
+
+    *buffer = malloc(exp_size);
+    gdTestAssert(*buffer != NULL);
+    act_size = fread(*buffer, sizeof(**buffer), exp_size, fp);
+    gdTestAssert(act_size == exp_size);
+
+    fclose(fp);
+    free(filename);
+
+    return act_size;
+}
```


_[1 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
