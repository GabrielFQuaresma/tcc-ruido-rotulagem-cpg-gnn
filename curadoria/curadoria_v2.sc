/* curadoria_v2.sc — traversal confirmatoria de erro de limites de buffer (CWE-119/120/125/787)
 *
 *   joern --script curadoria_v2.sc --param cpg_file=<X>.cpg.bin --param alvo=<funcao>
 *
 * ESTE SCRIPT NAO EMITE VEREDITO. Ele emite EVIDENCIA por funcao: contagens por categoria e
 * numero de fluxos por par (fonte, sink). O veredito e derivado depois pelo runner a partir de
 * regra_veredito.toml. Sem essa separacao, mudar a regra exigiria reescrever a traversal, e a
 * regra so pode ser fixada depois de ver a distribuicao da evidencia.
 *
 * INVARIANTE: nenhum identificador de projeto, nome de funcao de aplicacao ou id de CVE neste
 * arquivo nem nas tabelas de dados/. Regra que nao se rastreia ate a definicao da CWE ou ate a
 * libc veio da amostra e e overfitting.
 *
 * ARMADILHA: traversal do Joern e iterador de uso unico. Reusar um `val` de traversal devolve
 * vazio na segunda leitura, sem erro nenhum. Aqui tudo que percorre o CPG e `def`, nunca `val`.
 *
 * INDICES: as tabelas .tsv sao 0-indexadas (memcpy dest=0 src=1 size=2), o Joern e 1-indexado
 * para argumentos de chamada estatica. A conversao +1 acontece em UM lugar so: `argEm`.
 */

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Call}
import java.nio.file.{Files, Paths}
import scala.io.Source
import scala.util.Try

case class FuncMem(nome: String, categoria: String,
                   dest: Option[Int], src: Option[Int], size: Option[Int])

case class FonteLibc(nome: String, saida: Option[Int], viaRetorno: Boolean)

/** Tipos de estrutura de controle que TEM condicao. BREAK e ELSE nao tem, e por isso nao entram
  * na contagem de guardas (ver BASELINE_libgd.md: 13 IF + 3 WHILE + 1 FOR + 1 SWITCH = 18). */
val TIPOS_COM_CONDICAO = Set("IF", "WHILE", "FOR", "SWITCH", "DO")

def lerTsv(caminho: String): List[Map[String, String]] = {
  val fonte = Source.fromFile(caminho, "UTF-8")
  try {
    val linhas = fonte.getLines().filter(l => l.trim.nonEmpty).toList
    val cabecalho = linhas.head.split("\t").map(_.trim).toList
    linhas.tail.map(l => cabecalho.zip(l.split("\t", -1).map(_.trim).toList).toMap)
  } finally fonte.close()
}

def posicao(s: String): Option[Int] =
  if (s == null || s == "-" || s.isEmpty) None else Try(s.toInt).toOption

def esc(s: String): String =
  s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ")

def jsonNum(chave: String, v: Long): String = "\"" + esc(chave) + "\": " + v
def jsonStr(chave: String, v: String): String = "\"" + esc(chave) + "\": \"" + esc(v) + "\""
def jsonMapa(m: Map[String, Int]): String =
  "{" + m.toList.sortBy(_._1).map { case (k, v) => "\"" + esc(k) + "\": " + v }.mkString(", ") + "}"

@main def exec(cpg_file: String,
               alvo: String,
               dados: String = "dados",
               saida: String = "") = {

  // ---- tabelas -----------------------------------------------------------------------------
  val memRaw = lerTsv(Paths.get(dados, "funcoes_memoria.tsv").toString)
  val mapaMem: Map[String, FuncMem] = memRaw.map { r =>
    r("nome") -> FuncMem(r("nome"), r("categoria"),
      posicao(r("dest")), posicao(r("src")), posicao(r("size")))
  }.toMap

  val fontesRaw = lerTsv(Paths.get(dados, "fontes_nao_confiaveis.tsv").toString)
    .filter(r => r("tipo") != "estrutural") // a regra estrutural nao e nome de funcao
  val mapaFontes: Map[String, FonteLibc] = fontesRaw.map { r =>
    val bruto = r("saida")
    r("nome") -> FonteLibc(r("nome"), posicao(bruto), bruto == "ret")
  }.toMap

  // ---- CPG ---------------------------------------------------------------------------------
  val abriu = importCpg(cpg_file)
  if (abriu.isEmpty) {
    println("ERRO: nao consegui abrir o CPG: " + cpg_file)
    System.exit(2)
  }
  implicit val ec: EngineContext = EngineContext()

  def alvoM = cpg.method.nameExact(alvo)

  if (alvoM.size == 0) {
    println("ERRO: funcao alvo nao encontrada no CPG: " + alvo)
    System.exit(3)
  }

  /** Argumento na posicao 0-indexada da tabela. Unico ponto de conversao para o 1-indexado. */
  def argEm(c: Call, posTabela: Int): List[CfgNode] =
    c.argument.argumentIndex(posTabela + 1).l.collect { case n: CfgNode => n }

  // ---- camada 1: presenca ------------------------------------------------------------------
  def chamadasMem = alvoM.call.l.filter(c => mapaMem.contains(c.name))

  val porCategoria: Map[String, Int] =
    chamadasMem.groupBy(c => mapaMem(c.name).categoria).map { case (k, v) => (k, v.size) }
  val porNome: Map[String, Int] =
    chamadasMem.groupBy(_.name).map { case (k, v) => (k, v.size) }

  def acessosIndiretos = alvoM.call.nameExact("<operator>.indirectIndexAccess").l
  def acessosDiretos = alvoM.call.nameExact("<operator>.indexAccess").l

  // ---- guardas -----------------------------------------------------------------------------
  val estruturas: Map[String, Int] =
    alvoM.controlStructure.controlStructureType.l.groupBy(identity).map { case (k, v) => (k, v.size) }
  val condicoes = estruturas.filter { case (t, _) => TIPOS_COM_CONDICAO.contains(t) }.values.sum

  // ---- camada 2: fluxo ---------------------------------------------------------------------
  // Fontes. A estrutural (parametro) e sempre a mais ampla e a unica que sobra em projetos que
  // embrulham I/O em abstracao propria — ver a ameaca a validade no README de dados/.
  def fontesParametro: List[CfgNode] = alvoM.parameter.l.collect { case n: CfgNode => n }
  def fontesLibc: List[CfgNode] = alvoM.call.l.flatMap { c =>
    mapaFontes.get(c.name).toList.flatMap { f =>
      if (f.viaRetorno) List(c: CfgNode)
      else f.saida.toList.flatMap(i => argEm(c, i))
    }
  }

  // Sinks de memoria: ponteiro de destino, ponteiro de ORIGEM e tamanho. A origem entra porque a
  // familia declarada cobre CWE-125 (leitura fora de limites), e numa leitura fora de limites o
  // acesso indevido esta na origem. Ver BASELINE_libgd.md, secao "Baseline adotado".
  def sinksMemoria: List[CfgNode] = alvoM.call.l.flatMap { c =>
    mapaMem.get(c.name).filter(_.categoria != "alocacao").toList.flatMap { f =>
      List(f.dest, f.src, f.size).flatten.flatMap(i => argEm(c, i))
    }
  }
  def sinksAlocacao: List[CfgNode] = alvoM.call.l.flatMap { c =>
    mapaMem.get(c.name).filter(_.categoria == "alocacao").toList.flatMap { f =>
      f.size.toList.flatMap(i => argEm(c, i))
    }
  }
  // Sink de indice: argumento 2 (1-indexado) de indirectIndexAccess, ou seja, a expressao do indice.
  def sinksIndice: List[CfgNode] =
    acessosIndiretos.flatMap(c => c.argument.argumentIndex(2).l.collect { case n: CfgNode => n })

  def contarFluxos(sinks: List[CfgNode], fontes: List[CfgNode]): Int =
    if (sinks.isEmpty || fontes.isEmpty) 0
    else Try(sinks.iterator.reachableByFlows(fontes.iterator).size).getOrElse(-1)

  val fMemParam = contarFluxos(sinksMemoria, fontesParametro)
  val fMemLibc = contarFluxos(sinksMemoria, fontesLibc)
  val fIdxParam = contarFluxos(sinksIndice, fontesParametro)
  val fIdxLibc = contarFluxos(sinksIndice, fontesLibc)
  val fAlocParam = contarFluxos(sinksAlocacao, fontesParametro)
  val fAlocLibc = contarFluxos(sinksAlocacao, fontesLibc)

  // ---- saida -------------------------------------------------------------------------------
  def metodo = alvoM.head
  val json = List(
    jsonStr("alvo", alvo),
    jsonStr("arquivo", Try(metodo.filename).getOrElse("")),
    jsonNum("linha_inicio", Try(metodo.lineNumber.getOrElse(-1).toLong).getOrElse(-1L)),
    jsonNum("linha_fim", Try(metodo.lineNumberEnd.getOrElse(-1).toLong).getOrElse(-1L)),
    "\"camada1\": {" + List(
      "\"por_categoria\": " + jsonMapa(porCategoria),
      "\"por_nome\": " + jsonMapa(porNome),
      jsonNum("acessos_indexados", acessosIndiretos.size),
      jsonNum("acessos_indexados_diretos", acessosDiretos.size)
    ).mkString(", ") + "}",
    "\"camada2\": {" + List(
      jsonNum("fluxos_memoria_de_parametro", fMemParam),
      jsonNum("fluxos_memoria_de_libc", fMemLibc),
      jsonNum("fluxos_indice_de_parametro", fIdxParam),
      jsonNum("fluxos_indice_de_libc", fIdxLibc),
      jsonNum("fluxos_alocacao_de_parametro", fAlocParam),
      jsonNum("fluxos_alocacao_de_libc", fAlocLibc),
      jsonNum("sinks_memoria", sinksMemoria.size),
      jsonNum("sinks_indice", sinksIndice.size),
      jsonNum("fontes_parametro", fontesParametro.size),
      jsonNum("fontes_libc", fontesLibc.size)
    ).mkString(", ") + "}",
    "\"guardas\": {" + List(
      jsonNum("condicoes", condicoes),
      "\"estruturas\": " + jsonMapa(estruturas)
    ).mkString(", ") + "}",
    // Saude do CPG: permite ao regra_veredito.toml separar "nao achei padrao" de "nao consegui
    // olhar". Corpo nao parseado da blocos=0 e chamadas=0 com span>0 — medido em 07/08, os
    // sadios ficam em 2,6-5,1 nos por linha e os quebrados em 0,1. Numeros crus aqui; quem
    // decide o que e "degradado" e a config, nao a traversal.
    "\"saude\": {" + List(
      jsonNum("span", if (Try(metodo.lineNumberEnd.get > metodo.lineNumber.get).getOrElse(false))
        metodo.lineNumberEnd.get - metodo.lineNumber.get + 1 else 0),
      jsonNum("nos_ast", alvoM.ast.size),
      jsonNum("blocos", alvoM.block.astChildren.size),
      jsonNum("locais", alvoM.local.size),
      jsonNum("chamadas_total", alvoM.call.size),
      jsonNum("chamadas_nao_operador", alvoM.call.whereNot(_.name(".*<operator>.*")).size),
      jsonNum("estruturas_total", alvoM.controlStructure.size),
      "\"externo\": " + Try(metodo.isExternal).getOrElse(false)
    ).mkString(", ") + "}"
  ).mkString("{", ", ", "}")

  if (saida.nonEmpty) Files.write(Paths.get(saida), json.getBytes("UTF-8"))
  println("EVIDENCIA_JSON " + json)
}
