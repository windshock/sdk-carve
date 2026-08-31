// sdk-carve — reverse dependency trace / scope-completeness proof.
// Lists every type the carved SDK CALLS that is outside the in-scope packages and not a
// known library/framework. What remains should be framework or R8 compiler synthetics
// (e.g. shared StringBuilder helpers) — NOT missed SDK logic. If a real SDK package
// appears, add it to the carve globs and rebuild the CPG.
//
// Usage:  CPG=out/cpg.bin joern --script scope-closure.sc

importCpg(sys.env.getOrElse("CPG", "cpg.bin"))

// EDIT: your in-scope package prefixes (the carve globs, as dotted prefixes).
val inScope = List("com.smart.sklb.", "bg.", "cg.", "dg.")

// EDIT: extend for your ecosystem (added libs, ad SDKs, etc.).
val libs = List(
  "java.", "javax.", "android.", "androidx.", "dalvik.", "kotlin.", "kotlinx.",
  "sun.", "jdk.", "scala.", "com.google.", "retrofit2.", "okhttp3.", "okio.",
  "com.squareup.", "org.apache.", "com.coremedia.", "com.mixpanel.", "org.json."
)

val owners = cpg.call.methodFullName.l
  .map(_.split(":")(0))
  .map(s => if (s.contains(".")) s.substring(0, s.lastIndexOf('.')) else s)
  .distinct.sorted

val external = owners.filterNot(o => (inScope ++ libs).exists(o.startsWith))

println(s"distinct callee owners: ${owners.size}")
println(s"external (non-lib, non-in-scope): ${external.size}")
println("=== inspect each — should be framework or compiler synthetics only ===")
external.foreach(o => println("  " + o))
