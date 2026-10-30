/* exportar_grafos.sc — recorta o grafo de cada funcao alvo de dentro do CPG do arquivo.
 *
 *   joern --script exportar_grafos.sc --param cpg_file=<X>/cpg.bin \
 *         --param alvos=<lista.txt> --param saida=<dir>
 *
 * O QUE ELE IMPLEMENTA, e onde isso foi decidido
 * ----------------------------------------------
 * O CPG e do ARQUIVO inteiro (secao 4.3) e o ReVeal consome um grafo POR FUNCAO. O recorte foi
 * decidido no RECORTE_SUBGRAFO.md (16/08), apoiado em medida:
 *
 *   1. SUBGRAFO INDUZIDO pela funcao — o conjunto de nos e `method.ast`, so descendentes do no
 *      da funcao alvo. Nenhum no de outra funcao entra, qualquer que seja a contagem de aresta.
 *      E assim que o VAZAMENTO DE ROTULO fica impossivel POR CONSTRUCAO e nao improvavel por
 *      sorte: sem isto, o grafo de uma funcao negativa poderia conter os nos da funcao
 *      vulneravel do mesmo arquivo, e o modelo aprenderia "arquivo que contem vulnerabilidade".
 *   2. NAO SEGUIR `CALL`. E a aresta perigosa: segui-la traria a funcao vizinha para dentro.
 *      Aqui nao ha o que seguir — so entram arestas com AS DUAS PONTAS no conjunto de nos.
 *   3. TIPO COMO ATRIBUTO DE NO, nao como aresta. O EVAL_TYPE era 71% do que se perdia ao
 *      cortar, porque tipos moram no nivel do arquivo. O RECORTE_SUBGRAFO.md deixou isso como
 *      "hipotese, a conferir": CONFERIDO em 21/09/2026 — `typeFullName` e propriedade do no e
 *      sai sem seguir aresta nenhuma.
 *
 * O QUE ELE NAO FAZ: nao escolhe entre metodos homonimos. Exporta TODOS os candidatos com
 * corpo e deixa a escolha para o driver, que e quem tem o hash do corpo e a normalizacao
 * (normalizar_corpo.py). Duplicar essa logica aqui em Scala e como o projeto ja decidiu NAO
 * fazer com o extrator de nome.
 *
 * Saida: um <saida>/m<metodoId>.json por candidato, mais uma linha CAND por candidato no
 * stdout, para o driver saber o que existe.
 */

import io.shiftleft.codepropertygraph.generated.nodes
import java.io.{File, PrintWriter}

@main def exec(cpg_file: String, alvos: String, saida: String) = {
  val abriu = importCpg(cpg_file)
  if (abriu.isEmpty) {
    println("ERRO_ABRIR=" + cpg_file)
    System.exit(2)
  }

  new File(saida).mkdirs()

  val nomes = scala.io.Source.fromFile(alvos, "UTF-8").getLines()
    .map(_.trim).filter(_.nonEmpty).toList.distinct

  /** O tipo como ATRIBUTO. So os labels que de fato tem tipo; os demais (BLOCK, RETURN,
    * CONTROL_STRUCTURE, METHOD, FIELD_IDENTIFIER) nao tem tipo por natureza, nao por falha. */
  def tipoDe(n: nodes.AstNode): String = n match {
    case x: nodes.Call              => x.typeFullName
    case x: nodes.Identifier        => x.typeFullName
    case x: nodes.Literal           => x.typeFullName
    case x: nodes.Local             => x.typeFullName
    case x: nodes.MethodParameterIn => x.typeFullName
    case x: nodes.MethodParameterOut=> x.typeFullName
    case x: nodes.MethodReturn      => x.typeFullName
    case x: nodes.Member            => x.typeFullName
    case _                          => ""
  }

  def esc(s: String): String = {
    val sb = new StringBuilder
    s.foreach {
      case '"'  => sb.append("\\\"")
      case '\\' => sb.append("\\\\")
      case '\n' => sb.append("\\n")
      case '\r' => sb.append("\\r")
      case '\t' => sb.append("\\t")
      case c if c < ' ' => sb.append("\\u%04x".format(c.toInt))
      case c    => sb.append(c)
    }
    sb.toString
  }

  println("N_ALVOS=" + nomes.size)

  nomes.foreach { nome =>
    // so metodo interno e COM corpo pode virar grafo; declaracao sem bloco nao tem AST util
    val cands = cpg.method.nameExact(nome).l
      .filter(m => !m.isExternal && m.block.astChildren.size > 0)
    println("ALVO\t" + nome + "\t" + cands.size)

    cands.foreach { m =>
      val nos = m.ast.l
      val idx = nos.map(_.id).zipWithIndex.toMap      // id do CPG -> indice local 0..n-1
      val dentro = idx.keySet

      val arestas = nos.flatMap { n =>
        n.outE.l.collect {
          case e if dentro.contains(e.dst.id) => (idx(n.id), idx(e.dst.id), e.label)
        }
      }

      val pw = new PrintWriter(new File(saida, "m" + m.id + ".json"), "UTF-8")
      try {
        pw.print("{\"metodo_id\":" + m.id)
        pw.print(",\"nome\":\"" + esc(m.name) + "\"")
        pw.print(",\"full_name\":\"" + esc(m.fullName) + "\"")
        pw.print(",\"arquivo\":\"" + esc(m.filename) + "\"")
        pw.print(",\"linha_inicio\":" + m.lineNumber.getOrElse(-1))
        pw.print(",\"linha_fim\":" + m.lineNumberEnd.getOrElse(-1))
        pw.print(",\"n_nos\":" + nos.size + ",\"n_arestas\":" + arestas.size)
        pw.print(",\"nos\":[")
        nos.zipWithIndex.foreach { case (n, i) =>
          if (i > 0) pw.print(",")
          pw.print("{\"i\":" + i +
                   ",\"label\":\"" + esc(n.label) + "\"" +
                   ",\"tipo\":\"" + esc(tipoDe(n)) + "\"" +
                   ",\"linha\":" + n.lineNumber.getOrElse(-1) +
                   ",\"code\":\"" + esc(n.code) + "\"}")
        }
        pw.print("],\"arestas\":[")
        arestas.zipWithIndex.foreach { case ((a, b, lab), i) =>
          if (i > 0) pw.print(",")
          pw.print("[" + a + "," + b + ",\"" + esc(lab) + "\"]")
        }
        pw.print("]}")
      } finally pw.close()

      println("CAND\t" + nome + "\t" + m.id +
              "\t" + m.lineNumber.getOrElse(-1) +
              "\t" + m.lineNumberEnd.getOrElse(-1) +
              "\t" + nos.size + "\t" + arestas.size)
    }
  }
  println("FIM")
}
