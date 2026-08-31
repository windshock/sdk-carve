// Track 1 — scoped CPG taint queries for the SMARTLB/Goldoson edge SDK.
// Run: JAVA_HOME=<jdk17> joern --script edge-taint.sc
// Loads the scoped CPG built by jimple2cpg from edge-scoped.jar.

importCpg("/Users/1004276/Downloads/goldoson/analysis/joern/projects/edge-scoped/cpg.bin")

val srcNames = "getInstalledApplications|getHardwareAddress|getBondedDevices|" +
  "getConnectionInfo|getScanResults|getLastLocation|getAdvertisingIdInfo|" +
  "getLatitude|getLongitude|getAddress|getNetworkOperatorName|getBSSID|getSSID"
val snkNames = "putCol|getPdata|userJoin|getBConfig|isRunable|loadData|loadUrl|loadDataWithBaseURL"

println("========== CPG STATS ==========")
println(s"methods=${cpg.method.size}  calls=${cpg.call.size}  typeDecls=${cpg.typeDecl.size}")

println("\n========== SOURCES (device data reads) ==========")
cpg.call.name(srcNames).map(c => s"${c.name}%-26s".format(c.name) + s"  in ${c.method.fullName}")
  .distinct.sorted.foreach(println)

println("\n========== SINKS (network / webview) ==========")
cpg.call.name(snkNames).map(c => s"${c.name}%-22s".format(c.name) + s"  in ${c.method.fullName}")
  .distinct.sorted.foreach(println)

println("\n========== CALL-GRAPH REACHABILITY: onStartJob -> sinks ==========")
val entries = cpg.method.nameExact("onStartJob", "run", "c0", "g0", "e0", "G", "H")
val sinkMethods = cpg.call.name(snkNames).method.fullName.toSet
// which sink-bearing methods are reachable from the JobService entry set
val reach = entries.repeat(_.callee)(_.maxDepth(6).emit).fullName.toSet
snkNames.split('|').foreach { sn =>
  val hosts = cpg.call.name(sn).method.fullName.toSet
  val hit = hosts.exists(reach.contains)
  println(f"$sn%-20s reachable-from-entry=$hit  (hosts=${hosts.size})")
}

println("\n========== DATA FLOWS (source ~> sink) ==========")
val src = cpg.call.name(srcNames)
val snk = cpg.call.name(snkNames)
val flows = snk.reachableByFlows(src).l
println(s"flow count = ${flows.size}")
flows.take(25).foreach { p =>
  println("  " + p.elements.map(_.code.take(60)).mkString("  ~>  "))
}
