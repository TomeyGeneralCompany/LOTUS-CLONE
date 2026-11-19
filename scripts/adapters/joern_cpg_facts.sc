// Joern (Apache-2.0) CPG dataflow & sink query script for LOTUS ProgramFacts IR.
// Usage: joern --script scripts/adapters/joern_cpg_facts.sc --param cpgFile=/tmp/cpg.bin --param outFile=/tmp/out.json

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import java.nio.file.{Files, Paths}
import java.nio.charset.StandardCharsets

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  def esc(s: String): String =
    Option(s).getOrElse("")
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r")

  val sinkRegex = "(?i).*(exec|eval|system|popen|executeQuery|executeUpdate|ProcessBuilder|readObject|innerHTML|render_template_string|mark_safe).*"
  val methods = cpg.method.internal.l.take(400)
  val sinks = cpg.call.name(sinkRegex).l.take(200)
  val sources = cpg.method.internal.parameter.l.take(200)

  val flows = sinks.reachableByFlows(sources).l.take(100)

  val symJson = methods.map { m =>
    val line = m.lineNumber.getOrElse(1)
    val file = m.filename
    s"""{"name":"${esc(m.name)}","qualifiedName":"${esc(m.fullName)}","file":"${esc(file)}","line":$line}"""
  }.mkString(",")

  val sinkJson = sinks.map { c =>
    val line = c.lineNumber.getOrElse(1)
    val file = c.file.name.headOption.getOrElse("")
    val mname = c.method.name
    s"""{"name":"${esc(c.name)}","code":"${esc(c.code)}","file":"${esc(file)}","line":$line,"method":"${esc(mname)}"}"""
  }.mkString(",")

  val flowJson = flows.map { f =>
    val elems = f.elements.l
    val srcNode = elems.headOption
    val dstNode = elems.lastOption
    val srcFile = srcNode.flatMap(_.file.name.headOption).getOrElse("")
    val srcLine = srcNode.flatMap(_.lineNumber).getOrElse(1)
    val srcCode = srcNode.map(_.code).getOrElse("")
    val dstFile = dstNode.flatMap(_.file.name.headOption).getOrElse("")
    val dstLine = dstNode.flatMap(_.lineNumber).getOrElse(1)
    val dstCode = dstNode.map(_.code).getOrElse("")
    s"""{"sourceFile":"${esc(srcFile)}","sourceLine":$srcLine,"sourceCode":"${esc(srcCode)}","sinkFile":"${esc(dstFile)}","sinkLine":$dstLine,"sinkCode":"${esc(dstCode)}","steps":${elems.size}}"""
  }.mkString(",")

  val json = s"""{"adapter":"joern","methods":[$symJson],"sinks":[$sinkJson],"flows":[$flowJson]}"""
  Files.write(Paths.get(outFile), json.getBytes(StandardCharsets.UTF_8))
}
