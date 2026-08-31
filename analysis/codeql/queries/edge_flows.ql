/**
 * @name Goldoson SMARTLB device-data sources and network/WebView sinks
 * @description Enumerates on-device data reads (sources) and network/WebView
 *              exfiltration points (sinks) in the scoped SMARTLB/Goldoson SDK.
 *              build-mode=none leaves external types unresolved, so matching is
 *              by method name.
 * @kind problem
 * @problem.severity warning
 * @id goldoson/edge-flows
 */

import java

predicate isSource(MethodCall ma, string what) {
  ma.getMethod().hasName("getInstalledApplications") and what = "SOURCE installed-apps"
  or
  ma.getMethod().hasName("getHardwareAddress") and what = "SOURCE mac-address"
  or
  ma.getMethod().hasName("getBondedDevices") and what = "SOURCE bluetooth-bonded"
  or
  ma.getMethod().hasName("getConnectionInfo") and what = "SOURCE wifi-connection"
  or
  ma.getMethod().hasName("getScanResults") and what = "SOURCE wifi-scan"
  or
  ma.getMethod().hasName("getLastLocation") and what = "SOURCE gps-location"
  or
  ma.getMethod().hasName("getAdvertisingIdInfo") and what = "SOURCE advertising-id"
  or
  ma.getMethod().hasName("getBSSID") and what = "SOURCE wifi-bssid"
  or
  ma.getMethod().hasName("getSSID") and what = "SOURCE wifi-ssid"
  or
  ma.getMethod().hasName("getLatitude") and what = "SOURCE gps-latitude"
  or
  ma.getMethod().hasName("getLongitude") and what = "SOURCE gps-longitude"
  or
  ma.getMethod().hasName("getAddress") and what = "SOURCE bluetooth-address"
  or
  ma.getMethod().hasName("getNetworkOperatorName") and what = "SOURCE carrier"
}

predicate isSink(MethodCall ma, string what) {
  ma.getMethod().hasName("putCol") and what = "SINK putCol -> bhuroid.com (collection upload)"
  or
  ma.getMethod().hasName("getPdata") and what = "SINK getPdata -> bhuroid.com (ad HTML)"
  or
  ma.getMethod().hasName("userJoin") and what = "SINK userJoin -> bhuroid.com (register)"
  or
  ma.getMethod().hasName("getBConfig") and what = "SINK getBConfig -> bhuroid.com (remote config)"
  or
  ma.getMethod().hasName("isRunable") and what = "SINK isRunable -> bhuroid.com (gate)"
  or
  ma.getMethod().hasName("loadData") and what = "SINK WebView.loadData (server HTML exec)"
  or
  ma.getMethod().hasName("loadUrl") and what = "SINK WebView.loadUrl"
}

from MethodCall ma, string what
where isSource(ma, what) or isSink(ma, what)
select ma,
  what + "  @  " + ma.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    ma.getEnclosingCallable().getName()
