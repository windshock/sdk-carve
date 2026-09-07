importCpg("tnk.cpg")
def show(label:String, q: io.shiftleft.semanticcpg.language.NodeSteps[_])=()
println("\n########## SINK/SOURCE INVENTORY (CPG-level) ##########")
def inv(name:String, re:String) = {
  val calls = cpg.call.methodFullName(re).l
  println(f"\n== $name%-28s : ${calls.size} call-sites ==")
  calls.map(c => c.methodFullName).distinct.sorted.take(25).foreach(m => println("   callee: "+m))
  calls.map(c => c.method.fullName).distinct.sorted.take(25).foreach(m => println("   in:     "+m))
}
inv("NET (http/socket/okhttp)", ".*(openConnection|openStream|HttpURLConnection|OkHttpClient|okhttp3.*newCall|java.net.Socket|getOutputStream|URLConnection).*")
inv("EXEC (runtime/process)",   ".*(java.lang.Runtime.*exec|ProcessBuilder.*start|Os.*execve).*")
inv("DYNAMIC-LOAD",             ".*(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|System.*load|loadLibrary|ClassLoader.*loadClass).*")
inv("REFLECTION",              ".*(java.lang.reflect|Class.*forName|getDeclaredMethod|getMethod.*invoke|Method.*invoke).*")
inv("DESERIALIZATION",         ".*(ObjectInputStream.*readObject|XMLDecoder|XStream|readUnshared).*")
inv("SCRIPT-ENGINE (bsh/js)",  ".*(bsh|ScriptEngine|Interpreter.*eval|rhino|Nashorn).*")
inv("DEVICE-ID (source)",      ".*(getDeviceId|getSubscriberId|getSimSerialNumber|getImei|getMeid|getSerial|getMacAddress|Secure.*getString|getAdvertisingId|AdvertisingIdClient).*")
inv("LOCATION (source)",       ".*(getLastKnownLocation|requestLocationUpdates|getLatitude|getLongitude).*")

println("\n########## REACHABILITY: device-id/adid -> network sink ##########")
try {
  val src = cpg.call.methodFullName(".*(getDeviceId|getSubscriberId|getSimSerialNumber|getMacAddress|getAdvertisingId|AdvertisingIdClient.*getId).*")
  val snk = cpg.call.methodFullName(".*(openConnection|openStream|newCall|getOutputStream|java.net.Socket.*).*").argument
  val flows = snk.reachableByFlows(src).l
  println(s"device-id -> network flows: ${flows.size}")
  flows.take(8).foreach(f => println("  FLOW: " + f.elements.map(_.code).mkString(" ~> ").take(300)))
} catch { case e:Throwable => println("dataflow unavailable: "+e.getMessage) }
