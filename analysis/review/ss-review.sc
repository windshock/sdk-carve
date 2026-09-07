// Review source->sink + reachability for a carved SDK CPG.
// env: CPG (path). Prints collectors, sinks, decryptor evidence, and source->sink dataflow.
importCpg(sys.env("CPG"))
val SRC = Set("getDeviceId","getImei","getSubscriberId","getSimSerialNumber","getMacAddress",
  "getBSSID","getSSID","getScanResults","getBondedDevices","requestLocationUpdates",
  "getLastKnownLocation","getCurrentLocation","getInstalledPackages","getInstalledApplications",
  "queryIntentActivities","getRunningTasks","queryUsageStats","getPrimaryClip","getId")
val SNK = Set("newCall","enqueue","execute","openConnection","connect","loadUrl","loadData",
  "loadDataWithBaseURL","postUrl","evaluateJavascript","sendTextMessage")
val DEC = Set("doFinal","decrypt","decode")   // endpoint / string decryption evidence
def hits(names: Set[String]) = cpg.call.filter(c => names.contains(c.name)).l
val s = hits(SRC); val k = hits(SNK); val d = hits(DEC).filter(c => c.name=="doFinal" || c.methodFullName.toLowerCase.contains("crypto") || c.name=="decrypt")
println("== METHODS: " + cpg.method.size + " ==")
println("== COLLECTORS (" + s.size + ") ==")
s.groupBy(_.name).toList.sortBy(-_._2.size).foreach{case(n,cs)=> println(f"  $n%-24s ${cs.size}%3d  e.g. " + cs.head.method.fullName.take(80))}
println("== SINKS (" + k.size + ") ==")
k.groupBy(_.name).toList.sortBy(-_._2.size).foreach{case(n,cs)=> println(f"  $n%-24s ${cs.size}%3d  e.g. " + cs.head.method.fullName.take(80))}
println("== DECRYPT/CRYPTO call-sites (" + d.size + ") — endpoint/string decryption evidence ==")
d.groupBy(_.name).toList.sortBy(-_._2.size).foreach{case(n,cs)=> println(f"  $n%-20s ${cs.size}%3d")}
// dataflow: does a collector value reach a network/webview sink argument?
val flows = k.argument.reachableBy(s).size
println("== DATAFLOW collector -> sink (reachableBy): " + flows + " ==")
// call-graph reachability: sink methods reachable from a method that also hosts a collector
val srcMethods = s.method.fullName.toSet
val sinkReachFromSrc = k.method.dedup.l.count(m => m.caller.fullName.exists(srcMethods.contains) || srcMethods.contains(m.fullName))
println("== sink methods co-located-with/called-by a collector method: " + sinkReachFromSrc + " ==")
