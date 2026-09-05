/**
 * @name SDK source->sink taint flows
 * @description Sensitive-read source -> SDK upload/webview/network sink, taint-tracked with CodeQL's
 *              built-in flow-through models. Used to compare the flow SET carved vs whole-app.
 * @kind problem
 * @problem.severity warning
 * @id sdk-carve/dataflow
 */
import java
import semmle.code.java.dataflow.TaintTracking

module SdkCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(MethodCall c | c = n.asExpr() |
      c.getMethod().hasName([
        "getInstalledApplications", "getInstalledPackages", "getHardwareAddress", "getBondedDevices",
        "getAddress", "getConnectionInfo", "getScanResults", "getBSSID", "getSSID",
        "getLatitude", "getLongitude", "getNetworkOperatorName", "getDeviceId", "getImei",
        "getSimSerialNumber", "getSubscriberId", "getLine1Number", "getMacAddress"]))
  }
  predicate isSink(DataFlow::Node n) {
    exists(MethodCall c | n.asExpr() = c.getAnArgument() |
      c.getMethod().hasName([
        "putCol", "getPdata", "userJoin", "getBConfig", "getBList", "putList",
        "loadData", "loadUrl", "execute", "openConnection", "newCall", "write"]))
  }
  // Minimal within-SDK propagation model: an SDK method call propagates taint from its
  // arguments/qualifier to its result. The SDK serializes sensitive data through its own
  // (obfuscated) carriers that default taint models don't cover. Applied IDENTICALLY to carved
  // and whole-app, so it does not bias the fidelity (carved==whole-app) comparison.
  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // (a) SDK method call: args/qualifier -> result, AND arg -> qualifier (collector mutation:
    //     collector.put(sensitive) taints `collector`, later passed to the sink)
    exists(MethodCall c | inSdk(c.getMethod().getDeclaringType()) |
      (n2.asExpr() = c and (n1.asExpr() = c.getAnArgument() or n1.asExpr() = c.getQualifier()))
      or
      (n1.asExpr() = c.getAnArgument() and n2.asExpr() = c.getQualifier()))
    or
    // (b) SDK field: value stored -> any read (the collect-to-field-then-upload pattern)
    exists(Field f | inSdk(f.getDeclaringType()) |
      n1.asExpr() = f.getAnAssignedValue() and n2.asExpr() = f.getAnAccess())
  }
}

predicate inSdk(RefType t) {
  exists(string p | p = t.getPackage().getName() |
    p.matches("com.smart.sklb%") or p = "bg" or p = "cg" or p = "dg")
}

module SdkFlow = TaintTracking::Global<SdkCfg>;

from DataFlow::Node src, DataFlow::Node sink
where SdkFlow::flow(src, sink)
select sink,
  src.asExpr().(MethodCall).getMethod().getName() + " @ " +
  src.getEnclosingCallable().getQualifiedName() + "  ==>  " +
  sink.asExpr().getEnclosingCallable().getQualifiedName()
