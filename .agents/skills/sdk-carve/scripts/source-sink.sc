// sdk-carve — source/sink inventory + entry->sink reachability on a carved CPG.
// Usage:  CPG=out/cpg.bin joern --script source-sink.sc
// EDIT the three lists below for your target (defaults = Goldoson/SMARTLB example).

importCpg(sys.env.getOrElse("CPG", "cpg.bin"))

// EDIT: device-data reads / tainted-input APIs for your target.
val srcNames = "getInstalledApplications|getHardwareAddress|getBondedDevices|" +
  "getConnectionInfo|getScanResults|getLastLocation|getAdvertisingIdInfo|" +
  "getLatitude|getLongitude|getAddress|getBSSID|getSSID|getNetworkOperatorName"
// EDIT: network / exec / exfiltration APIs for your target.
val snkNames = "putCol|getPdata|userJoin|getBConfig|isRunable|loadData|loadUrl|loadDataWithBaseURL"
// EDIT: entry points (service/lifecycle/orchestrator methods).
val entryNames = List("onStartJob", "run")

println(s"methods=${cpg.method.size}  calls=${cpg.call.size}  typeDecls=${cpg.typeDecl.size}")

println("\n== SOURCES ==")
cpg.call.name(srcNames).map(c => c.name + "  @  " + c.method.fullName).distinct.sorted.foreach(println)

println("\n== SINKS ==")
cpg.call.name(snkNames).map(c => c.name + "  @  " + c.method.fullName).distinct.sorted.foreach(println)

println("\n== ENTRY -> SINK reachability ==")
val reach = cpg.method.nameExact(entryNames: _*).repeat(_.callee)(_.maxDepth(8).emit).fullName.toSet
snkNames.split('|').foreach { s =>
  val hosts = cpg.call.name(s).method.fullName.toSet
  println(f"$s%-22s reachable-from-entry=${hosts.exists(reach.contains)}  (call-sites=${hosts.size})")
}

// Fine-grained taint (often 0 across SharedPreferences/DTO constructors — needs flow models):
println("\n== fine-grained flows (source ~> sink) ==")
println(s"flow count = ${cpg.call.name(snkNames).reachableByFlows(cpg.call.name(srcNames)).size}")
