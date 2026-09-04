importCpg(sys.env("CPG"))
val roots = sys.env("ROOTS").split(",").map(_.trim).filter(_.nonEmpty)
val re = if (roots.isEmpty) "$^" else roots.map(r => "^" + java.util.regex.Pattern.quote(r) + "\\..*").mkString("|")
val tmeth = cpg.method.fullName(re).size            // methods under the target SDK root(s) — anchored
val own   = cpg.call.name(sys.env("OWN")).size      // SDK-own sink names (putCol/getBConfig/getPdata/userJoin)
println(s"QRES td=${cpg.typeDecl.size} target_methods=$tmeth own_sink_cs=$own")
