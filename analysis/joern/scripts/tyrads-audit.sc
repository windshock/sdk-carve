// tyrads-audit.sc — CPG danger inventory for the carved Tyrads SDK (com/tyrads/sdk).
// Method-call references survive xShield string-vaulting, so this is a stronger check than a
// plaintext regex scan. Build: carve com/tyrads/sdk/* from com.skplanet.ocb.locker -> jimple2cpg.
// Run:  joern --script analysis/joern/scripts/tyrads-audit.sc   (adjust the CPG path below)
importCpg("workspace/tyrads.cpg/cpg.bin")
Seq(
 ("EXEC",           ".*(Runtime.*exec|ProcessBuilder.*start).*"),
 ("SCRIPT-ENGINE",  ".*(bsh|ScriptEngine|Interpreter.*eval|rhino).*"),
 ("DYNAMIC-LOAD",   ".*(DexClassLoader|PathClassLoader|loadLibrary|ClassLoader.*loadClass).*"),
 ("DESERIALIZE",    ".*(ObjectInputStream.*readObject|XMLDecoder|XStream).*"),
 ("REFLECTION",     ".*(reflect.Method.*invoke|Class.*forName|getDeclaredMethod).*"),
 ("DEVICE-ID",      ".*(getDeviceId|getSubscriberId|getSimSerial|getMacAddress|getAdvertisingId).*"),
 ("USAGE-STATS",    ".*(UsageStatsManager|queryUsageStats|queryEvents).*"),
 ("JS-BRIDGE",      ".*(addJavascriptInterface|evaluateJavascript).*"),
 ("NET",            ".*(openConnection|newCall|java.net.Socket|getOutputStream).*")
).foreach { case (n, re) =>
  val c = cpg.call.methodFullName(re).l
  println("INV|" + n + "|" + c.size + "|" + c.map(_.methodFullName).distinct.take(4).mkString(" ; ").take(150))
}
