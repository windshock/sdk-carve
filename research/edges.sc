// Dump the target SDK's call-graph edges from a CPG, split into:
//   E <caller> <callee>   internal edge (SDK method -> SDK method)
//   B <caller> <callee>   boundary edge (SDK method -> non-SDK callee; carved => stub)
// env: CPG (cpg path), ROOTS (comma-separated dotted SDK roots), OUT (output file)
importCpg(sys.env("CPG"))
val roots = sys.env("ROOTS").split(",").map(_.trim).filter(_.nonEmpty).toList
def isSdk(fn: String): Boolean = fn != null && roots.exists(r => fn.startsWith(r + "."))
val re = roots.map(r => "^" + java.util.regex.Pattern.quote(r) + "\\..*").mkString("|")
val sdkMethods = cpg.method.fullName(re).l
val pw = new java.io.PrintWriter(sys.env("OUT"))
var e = 0; var b = 0
sdkMethods.foreach { m =>
  m.call.l.foreach { c =>
    val callee = c.methodFullName
    if (isSdk(callee)) { pw.println("E\t" + m.fullName + "\t" + callee); e += 1 }
    else { pw.println("B\t" + m.fullName + "\t" + callee); b += 1 }
  }
}
pw.close()
println(s"FIDELITY methods=${sdkMethods.size} internal_edges=$e boundary_edges=$b")
