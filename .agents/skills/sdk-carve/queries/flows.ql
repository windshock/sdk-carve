/**
 * @name Embedded-SDK sources and sinks (name-matched)
 * @description Enumerates on-device data reads (sources) and network/exec sinks in a
 *              scoped SDK CodeQL database. With build-mode=none, external types
 *              (framework/Retrofit/OkHttp) are unresolved, so matching is by method NAME.
 *              EDIT the predicates for your target (defaults = Goldoson/SMARTLB example).
 * @kind problem
 * @problem.severity warning
 * @id sdk-carve/flows
 */

import java

predicate isSource(MethodCall c, string what) {
  c.getMethod().hasName("getInstalledApplications") and what = "SOURCE installed-apps" or
  c.getMethod().hasName("getHardwareAddress")       and what = "SOURCE mac-address" or
  c.getMethod().hasName("getBondedDevices")         and what = "SOURCE bluetooth-bonded" or
  c.getMethod().hasName("getAddress")               and what = "SOURCE bluetooth-address" or
  c.getMethod().hasName("getConnectionInfo")        and what = "SOURCE wifi-connection" or
  c.getMethod().hasName("getScanResults")           and what = "SOURCE wifi-scan" or
  c.getMethod().hasName("getBSSID")                 and what = "SOURCE wifi-bssid" or
  c.getMethod().hasName("getSSID")                  and what = "SOURCE wifi-ssid" or
  c.getMethod().hasName("getLatitude")              and what = "SOURCE gps-lat" or
  c.getMethod().hasName("getLongitude")             and what = "SOURCE gps-lon" or
  c.getMethod().hasName("getNetworkOperatorName")   and what = "SOURCE carrier"
}

predicate isSink(MethodCall c, string what) {
  c.getMethod().hasName("putCol")     and what = "SINK collection-upload" or
  c.getMethod().hasName("getPdata")   and what = "SINK ad-html-fetch" or
  c.getMethod().hasName("userJoin")   and what = "SINK register" or
  c.getMethod().hasName("getBConfig") and what = "SINK remote-config" or
  c.getMethod().hasName("isRunable")  and what = "SINK gate" or
  c.getMethod().hasName("loadData")   and what = "SINK webview-html-exec" or
  c.getMethod().hasName("loadUrl")    and what = "SINK webview-url"
}

from MethodCall c, string what
where isSource(c, what) or isSink(c, what)
select c,
  what + "  @  " + c.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    c.getEnclosingCallable().getName()
