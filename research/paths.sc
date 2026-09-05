// Source->sink fidelity: within the target SDK, count sensitive-source call-sites, sink call-sites,
// and TRUE dataflow paths (sink reachableBy source). Compare carved vs whole-app.
// env: CPG, ROOTS (comma dotted)
importCpg(sys.env("CPG"))
val roots = sys.env("ROOTS").split(",").map(_.trim).filter(_.nonEmpty).toList
val re = roots.map(r => "^" + java.util.regex.Pattern.quote(r) + "\\..*").mkString("|")
val srcRe = "getInstalledApplications|getHardwareAddress|getBondedDevices|getAddress|getConnectionInfo|" +
            "getScanResults|getBSSID|getSSID|getLatitude|getLongitude|getNetworkOperatorName|getDeviceId|getImei|getLine1Number"
val sinkRe = "loadUrl|loadData|putCol|getPdata|userJoin|getBConfig|openConnection|exec|execute|newCall"
// re-query cpg each time (Traversal is single-use)
val srcCalls  = cpg.method.fullName(re).call.name(srcRe).l
val sinkCalls = cpg.method.fullName(re).call.name(sinkRe).l
val srcMethods  = cpg.method.fullName(re).filter(_.call.name(srcRe).nonEmpty).fullName.toSet
val sinkMethods = cpg.method.fullName(re).filter(_.call.name(sinkRe).nonEmpty).fullName.toSet
// true dataflow: sink args reachableBy source calls
val df = try { sinkCalls.reachableBy(srcCalls).size } catch { case _: Throwable => -1 }
val pw = new java.io.PrintWriter(sys.env("OUT"))
srcMethods.foreach(m => pw.println("SRC\t" + m)); sinkMethods.foreach(m => pw.println("SINK\t" + m))
pw.close()
println(s"PATHS source_sites=${srcCalls.size} sink_sites=${sinkCalls.size} " +
        s"source_methods=${srcMethods.size} sink_methods=${sinkMethods.size} dataflows=$df")
