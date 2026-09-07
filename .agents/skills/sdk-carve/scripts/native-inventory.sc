// sdk-carve (native track) — imported-API surface + security-relevant sinks from a
// ghidra2cpg CPG (the native analog of the JVM source/sink inventory).
//
// Usage:  CPG=out/libfoo.cpg joern --script native-inventory.sc 2>&1 | grep -a '^MARK'
//
// OUTPUT PLUMBING: joern writes INFO logs to stdout and Ghidra literals contain NUL
// bytes, so plain grep treats the stream as binary. Every result line is prefixed
// with "MARK"; extract with `grep -a '^MARK'`.

importCpg(sys.env.getOrElse("CPG", "native.cpg"))

println("MARK stats methods=" + cpg.method.size + " calls=" + cpg.call.size +
  " literals=" + cpg.literal.size)

// Imported / external symbols = the native API surface. Skip Ghidra pseudo-ops
// (<operator>.*) and register placeholders.
println("MARK -- imported API surface --")
cpg.method.external.name.distinct
  .filterNot(n => n.startsWith("<operator>") || n.matches("x[0-9]+") || n == "UNKNOWN")
  .sorted.foreach(n => println("MARK.api " + n))

// EDIT: security-relevant native sinks for your target (exec/net/fs/mem/crypto/JNI/log).
val sinkRx = "(?i).*(system|exec|popen|fork|dlopen|dlsym|socket|connect|send|recv|" +
  "fopen|open|read|write|remove|unlink|memcpy|memmove|strcpy|strcat|sprintf|" +
  "AES|DES|MD5|SHA|EVP_|RSA|RC4|RegisterNatives|GetStringUTFChars|NewStringUTF|" +
  "FindClass|CallObjectMethod|GetMethodID|__android_log|__system_property).*"
println("MARK -- security-relevant calls --")
cpg.call.name.filter(_.matches(sinkRx)).distinct.sorted.foreach(n => println("MARK.sink " + n))

// Exported functions are the native entry points (JNI_OnLoad, Java_* for JNI).
println("MARK -- exported entry points --")
cpg.method.isExternal(false).name.filter(n => n.startsWith("Java_") || n.contains("JNI_OnLoad"))
  .distinct.sorted.foreach(n => println("MARK.entry " + n))
