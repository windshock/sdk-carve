#!/usr/bin/env python3
"""Per-class capability-API + endpoint mapping on a carved mini-JAR — the fast deep pass.

Answers "WHICH class reads WHAT and talks WHERE" in seconds, without a CPG. Complements
detect.py (root location) and the Joern/CodeQL passes (call-graph evidence): run this
first on every carve, then escalate the interesting ones to the full pipeline.

Usage: class-map.py <scoped.jar> [more.jar ...]
Output: one line per class that references a known collector/sink API or an endpoint,
with the API names and the hardcoded hosts found in its constant pool.
"""
import re, sys, zipfile

APIS = [
    # collectors (framework names are un-renameable)
    "getScanResults", "getBSSID", "getSSID", "getConnectionInfo", "getBluetoothLeScanner",
    "startScan", "startLeScan", "onLeScan", "getBondedDevices", "getLastKnownLocation",
    "getLastLocation", "requestLocationUpdates", "getLatitude", "getLongitude",
    "getDeviceId", "getImei", "getAndroidId", "getAdvertisingIdInfo", "getMacAddress",
    "getHardwareAddress", "getInstalledApplications", "getInstalledPackages",
    "getRunningTasks", "queryIntentActivities", "getPrimaryClip", "getCellLocation",
    # persistence / entries / evasion
    "onReceive", "onStartJob", "setRepeating", "SharedPreferences", "DexClassLoader",
    "isDebuggerConnected",
    # sinks
    "newCall", "openConnection", "loadUrl", "setJavaScriptEnabled",
    "evaluateJavascript", "sendTextMessage",
]
URL = re.compile(r"https?://[\w./:%#~?=&-]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:co\.kr|com|net|io|kr)\b")
NOISE = re.compile(r"(w3|apache|xmlpull|json|w3c|ietf|xml\.org)\.")

for jar in sys.argv[1:]:
    print(f"===== {jar} =====")
    with zipfile.ZipFile(jar) as z:
        for e in z.infolist():
            if not e.filename.endswith(".class"):
                continue
            s = z.read(e).decode("latin-1")
            apis = [a for a in APIS if a in s]
            urls = sorted({u.rstrip("/").rstrip("\\") for u in URL.findall(s) if not NOISE.search(u)})
            if apis or urls:
                print(f"{e.filename[:-6]:58s} {'|'.join(apis[:9]):58s} {'  '.join(urls[:4])}")
