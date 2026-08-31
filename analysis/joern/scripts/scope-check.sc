importCpg("/Users/1004276/Downloads/goldoson/analysis/joern/projects/edge-scoped/cpg.bin")
// SDK 코드가 호출하는 모든 callee의 소유 타입
val owners = cpg.call.methodFullName.l
  .map(s => s.split(":")(0))            // "owner.method:sig" -> "owner.method"
  .map(s => if (s.contains(".")) s.substring(0, s.lastIndexOf('.')) else s)
  .distinct.sorted
owners.foreach(o => println("OWNER\t" + o))
