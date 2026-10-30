# Por que algumas funções não têm grafo: o `#ifdef` sem header

Fechado em **21/09/2026**. Scripts: `_analisar_falhas.py`, `_listar_metodos.sc`,
`_experimento_ifdef.sh`, `_experimento_macros.py`, `_medir_parse_positivos.py`.

Responde a pergunta que o `LOCALIZACAO.md` deixou aberta — *por que* uma função não vira grafo —
e descobre, no caminho, que a causa **também atinge os positivos e portanto a curadoria**.

## Situando: três modos de falha que estavam no mesmo balde

"Não localizado" era um rótulo só para coisas diferentes. Separados:

| modo | o que é | n (de 1302) |
| --- | --- | --- |
| `so_declaracao` | o método **está** no CPG, nome certo, linhas certas — e **sem corpo** | 127 (9,8%) |
| `sem_metodo` | o `nameExact` devolveu zero | 35 (2,7%) |
| `sem_hash_1` | nome casou, corpo não bate | 299 (23,0%) |

Pelo critério adotado (alternativo), `sem_hash_1` **conta como localizado**. Então a falha que
sobra são 162 casos, e **127 deles (78%) são `so_declaracao`** — método presente, corpo ausente.

**Não é erro de nome.** É a pergunta deste registro.

## A causa, provada em experimento controlado

**O CPG é gerado de um `.c` sozinho, sem os headers do projeto.** Toda macro de configuração
(`PNG_WRITE_SUPPORTED`, `MAGICKCORE_TIFF_DELEGATE`, …) fica indefinida, o `#ifdef` que a testa
avalia falso, e tudo lá dentro vira **código inativo**: o Joern indexa a assinatura da função e
não produz corpo.

Isso não é dedução a partir de correlação. É experimento: mesmo arquivo, duas versões, a segunda
com **uma linha** a mais definindo **uma** macro.

| arquivo | macro definida | métodos com corpo, antes | depois |
| --- | --- | --- | --- |
| `pngwutil.c` (Chrome/libpng) | `PNG_WRITE_SUPPORTED` | **1** de 42 | **17** de 42 |
| `tiff.c` (ImageMagick) | `MAGICKCORE_TIFF_DELEGATE` | **4** de 39 | **35** de 39 |

O sintoma bate exatamente: em `pngwutil.c` as 42 assinaturas estão todas lá, com as linhas
corretas, e o único método com corpo é o `<global>` cobrindo o arquivo inteiro (1–2832).

**Onde dói:** os 7 arquivos com menos de 50% dos corpos parseados concentram **92 dos 127**
`so_declaracao`. A perda não está espalhada — está nesses arquivos.

## O mesmo problema atinge os positivos — e isso é sobre a curadoria

Medido em `_medir_parse_positivos.py`: **amostra de 85 itens positivos, semente 404**, abre o CPG
e pergunta só se o método alvo tem corpo. **Não lê veredito, não recalcula evidência, não julga.**

| | n | % |
| --- | --- | --- |
| o método alvo **tem** corpo | 78 | 91,8% |
| o método alvo existe e **não tem corpo** | **7** | **8,2%** |
| `nameExact` devolveu zero | 0 | 0% |

Mediana da saúde do CPG nos itens positivos: **90,0%**; 6 dos 85 itens com menos de 50%.

**O que este 8,2% significa, e é preciso ser exato:** em 1 de cada 12 positivos, a função não
tem corpo no grafo — logo não tem chamada, nem nó de AST, nem fluxo. **A traversal não podia
achar evidência nenhuma.** Nesses itens, "não confirmado" não quer dizer "sem evidência", quer
dizer **"não deu para olhar"**.

**O que este 8,2% NÃO é:** não é taxa de erro da curadoria, não é ruído de rótulo, não é
qualidade da regra. É o **piso de cegueira da ferramenta**.

### E a omissão é seletiva

| projeto | itens na amostra | cegos |
| --- | --- | --- |
| tcpdump | 6 | 17% |
| Chrome | 17 | 12% |
| Android | 24 | 4% |
| linux, ImageMagick, ghostscript, iperf, git | 3–4 cada | 0% |

Os itens cegos são reconhecíveis: `png_read_finish_row` e `png_set_PLTE` (libpng dentro do
Chrome), `METHODDEF` (libjpeg-turbo, que é macro), `juniper_mlppp_print` (tcpdump).

**Isto tem consequência direta numa frase do projeto.** A regra diz que *o silêncio da traversal
nunca inverte rótulo* e que *errar por omissão é de graça*. A regra continua valendo — nada aqui
inverte rótulo nenhum. Mas **"de graça" só vale se a omissão for aleatória**, e ela não é: se
concentra em projetos que guardam código com `#ifdef`. É a mesma assinatura já registrada duas
vezes — o `gdGetBuf` do `BASELINE_libgd.md` e os 9 de 10 Android do `COLISAO_NOME.md`.

**Vai para as Ameaças à Validade com esta redação:** o `M_cur` é enviesado contra projetos que
usam compilação condicional, porque neles a ferramenta não conseguiu olhar. n=85, 8,2%.

## Existe conserto genérico? Sim, e ele tem um preço sério

Escolher a macro à mão por arquivo colocaria nome de projeto dentro do pipeline — porta que não
vale abrir. A heurística testada é **genérica e sai do próprio arquivo**: definir toda macro que
o arquivo **testa** e nunca **define**. Entram `#ifdef X` e `#if defined(X)`; ficam de fora
`#ifndef X` e `#if !defined(X)`, e qualquer macro usada nos dois sentidos.

| arquivo | projeto | corpos antes | corpos depois | macros |
| --- | --- | --- | --- | --- |
| `pngwutil.c` | Chrome | 1/42 | **40/42** | 30 |
| `tiff.c` | ImageMagick | 4/39 | **24/26** | 25 |
| `tiff.c` | ImageMagick | 4/38 | **22/24** | 26 |
| `png.c` | ImageMagick | 8/56 | **12/27** | 34 |
| `e_aes.c` | openssl | 67/155 | **74/146** | 18 |
| `nf_defrag_ipv6_hooks.c` | linux | 3/8 | 3/8 | 0 |
| `print-isakmp.c` | tcpdump | 27/55 | 27/55 | 1 |

**Agregado: 114 → 202 corpos.** Funciona.

**E agora o preço, que está na coluna que é fácil não ver: o denominador muda.** `tiff.c` vai de
39 métodos para 26; `png.c` de 56 para 27. **Definir uma macro fecha o `#else` dela**, e os
métodos que viviam ali somem. O grafo fica **diferente**, não simplesmente maior — e "definir
toda macro de teste positivo" **não é a mesma coisa que compilar o projeto**: abre caminho de
plataforma e de depuração que o build real nunca abriria.

### DECIDIDO em 21/09/2026: **declarar e seguir**. Não regerar.

**Decisão do autor.** Os CPGs **não** são regerados. Ficam como estão, e o problema vai para as
Ameaças à Validade.

**O que isso mantém:** os 14.133 negativos de treino do `LOCALIZACAO.md`, a evidência da
curadoria congelada desde 10/08, e a Etapa 5 (precisão do filtro nos 50: 11/17 = 64,7% contra
taxa base 19/43 = 44,2%) — tudo intacto, nada refeito.

**O que isso custa:** a cobertura perdida não é recuperada. 9,8% dos negativos e 8,2% dos
positivos continuam fora por cegueira de ferramenta, seletivamente por projeto.

**Por que é a escolha certa:** o ganho seria cobertura de dataset; o custo seria refazer o
resultado que o trabalho existe para medir. E o viés não fica escondido — fica escrito.

### Por que não regerar, em detalhe

Adotar significaria:

1. **Regerar os CPGs** — custo já conhecido, ~7,8 h de Joern.
2. **Recalcular a evidência da curadoria**, que está **congelada desde 10/08**.
3. **Refazer a Etapa 5** — a precisão do filtro nos 50 (11/17 = 64,7% contra taxa base
   19/43 = 44,2%) foi medida sobre a evidência congelada. Mudar o grafo por baixo a invalida.

Isso é decisão de desenho com efeito em resultado congelado, e **não é decisão de script**.
Nada foi alterado. O experimento existe para que a decisão seja tomada com número à vista.

**Se for adotado, a ordem importa:** medir primeiro o efeito no veredito num dev set, nunca nos
50 — pelo mesmo motivo de sempre.

## O que muda a partir daqui

- **Para o dataset:** a perda de 9,8% por `so_declaracao` tem causa conhecida e conserto
  possível. Enquanto não houver decisão, o número do `LOCALIZACAO.md` (87,6%, pool de treino
  14.133) segue valendo.
- **Para o artigo:** entra uma Ameaça à Validade nova e específica — **8,2% dos positivos eram
  cegos por construção, seletivamente por projeto**. Ela não derruba nenhum resultado, mas
  qualifica a frase "errar por omissão é de graça", que hoje está sem ressalva.
- ~~Decisão em aberto~~ — **decidido: declarar e seguir** (seção acima). Não há mais decisão
  pendente nesta frente. **Próximo passo: montar o dataset de verdade** e trocar as estimativas
  do `LOCALIZACAO.md` pelas contagens.

## Parágrafo pronto para as Ameaças à Validade

> A geração dos CPGs processa cada arquivo-fonte isoladamente, sem os cabeçalhos do projeto a
> que pertence. Em consequência, macros de configuração testadas por diretivas de compilação
> condicional permanecem indefinidas, e o corpo das funções por elas guardadas é tratado como
> código inativo: o Joern registra a assinatura da função, mas não produz o grafo do corpo.
> Verificou-se experimentalmente que a definição de uma única macro eleva o número de corpos
> reconstruídos de 1 para 17 em `pngwutil.c` (libpng) e de 4 para 35 em `tiff.c` (ImageMagick).
> Numa amostra de 85 funções positivas, 8,2% encontravam-se nessa condição — isto é, a consulta
> de curadoria não dispunha de grafo sobre o qual buscar evidência. Esses casos não produzem
> rótulo incorreto, uma vez que o silêncio da consulta nunca inverte rótulo; produzem omissão.
> A omissão, porém, **não é aleatória**: concentra-se em projetos que empregam compilação
> condicional (tcpdump 17%, Chrome 12%, Android 4%, demais projetos 0% na amostra). O conjunto
> curado é, portanto, enviesado contra esses projetos, e a afirmação de que errar por omissão
> não tem custo deve ser lida com essa ressalva.
