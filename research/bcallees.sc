// Dump the SDK's boundary callees (SDK method -> non-SDK callee fullName), unique.
// env: CPG, ROOTS (comma dotted), OUT
importCpg(sys.env("CPG"))
val roots = sys.env("ROOTS").split(",").map(_.trim).filter(_.nonEmpty).toList
def isSdk(fn: String): Boolean = fn != null && roots.exists(r => fn.startsWith(r + "."))
val re = roots.map(r => "^" + java.util.regex.Pattern.quote(r) + "\\..*").mkString("|")
val pw = new java.io.PrintWriter(sys.env("OUT"))
cpg.method.fullName(re).call.l.foreach { c =>
  val callee = c.methodFullName
  if (!isSdk(callee)) pw.println(callee)
}
pw.close()
println("done")
