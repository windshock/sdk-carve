// adison-audit.sc — CPG danger inventory for the Adison offerwall SDK (co.adison.offerwall).
// Build: adison AAR 3.16.4 -> classes.jar -> jimple2cpg -o adison.cpg.  Run:
//   joern --script analysis/joern/scripts/adison-audit.sc   (adjust importCpg path below)
importCpg("adison.cpg")
Seq(
 ("EXEC",                       ".*(Runtime.*exec|ProcessBuilder.*start).*"),
 ("SCRIPT/DYN-LOAD",            ".*(bsh|ScriptEngine|DexClassLoader|ClassLoader.*loadClass|System.*load).*"),
 ("DESERIALIZE",                ".*(ObjectInputStream.*readObject|readExternal|XMLDecoder|XStream).*"),
 ("REFLECT-forName/newInstance",".*(Class.*forName|.*\\.newInstance).*"),
 ("DEVICE-ID",                  ".*(getDeviceId|getSubscriberId|getSimSerial|getMacAddress|getAdvertisingId).*"),
 ("NET",                        ".*(openConnection|okhttp3.*newCall|java.net.Socket).*")
).foreach { case (n, re) =>
  val c = cpg.call.methodFullName(re).l
  println("INV|" + n + "|" + c.size + "|" +
    c.map(x => x.method.name + "->" + x.methodFullName.split(":").head.split("\\.").takeRight(2).mkString(".")).distinct.take(6).mkString(" ; ").take(170))
}
