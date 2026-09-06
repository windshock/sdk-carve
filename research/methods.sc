// Dump the target SDK's method fullNames (for exact method-set diff carved vs whole-app).
// env: CPG, ROOTS (comma dotted), OUT
importCpg(sys.env("CPG"))
val roots = sys.env("ROOTS").split(",").map(_.trim).filter(_.nonEmpty).toList
val re = roots.map(r => "^" + java.util.regex.Pattern.quote(r) + "\\..*").mkString("|")
val pw = new java.io.PrintWriter(sys.env("OUT"))
cpg.method.fullName(re).fullName.dedup.l.sorted.foreach(pw.println)
pw.close()
println("done")
