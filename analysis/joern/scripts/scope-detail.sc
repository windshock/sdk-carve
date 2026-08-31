importCpg("/Users/1004276/Downloads/goldoson/analysis/joern/projects/edge-scoped/cpg.bin")
println("=== 5개 외부 호스트 클래스에 대한 실제 호출(호출자 위치 포함) ===")
cpg.call.methodFullName("(b7|g4|i1|w1)\\..*").l
  .map(c => c.methodFullName + "   <-- " + c.method.fullName)
  .distinct.sorted.foreach(println)
