#!/usr/bin/env python3
"""Family-agnostic triage: which package roots in a dex2jar JAR are spyware-SHAPED?

Scans every class's bytecode for un-renameable framework API signatures (collectors,
exfil sinks, persistence, dynamic loading, evasion), clusters hits per package root,
and flags roots with a collector+sink shape. Knows nothing about any malware family —
it finds *capability shapes*, so it works when no IOC list or family detector exists.

Usage: behavior-sweep.py <app-dex2jar.jar> [more.jar ...] [--min-collectors N]
Exit 0 = at least one FLAG (carve it next, see SKILL.md Method), 1 = none flagged.

A FLAG is a *lead generator*, not a verdict: carve the root and run the
source/sink/reachability pass to produce the behavior report. Common ad/analytics
prefixes are annotated '~' (they collect by design; verify, usually benign).
"""
from __future__ import annotations
import re, sys, zipfile
from collections import defaultdict

CATEGORIES: dict[str, list[str]] = {
    "collect.location":  ["requestLocationUpdates", "getLastKnownLocation", "getCurrentLocation"],
    "collect.identity":  ["getDeviceId", "getImei", "getMeid", "getSubscriberId",
                          "getSimSerialNumber", "getSimOperator", "getAndroidId",
                          "android_id", "AdvertisingIdClient", "getMacAddress"],
    "collect.netsurvey": ["getScanResults", "getBondedDevices", "getBluetoothLeScanner",
                          "startDiscovery", "getAllCellInfo", "getNeighboringCellInfo",
                          "getCellLocation"],
    "collect.applist":   ["getInstalledPackages", "getInstalledApplications",
                          "getRunningTasks", "getRunningAppProcesses", "queryIntentActivities"],
    "collect.content":   ["getPrimaryClip", "content://sms", "ContactsContract", "CallLog",
                          "AudioRecord", "AccessibilityService"],
    "sink.network":      ["openConnection", "Ljava/net/Socket;", "DatagramSocket",
                          "Lokhttp3/", "Lretrofit2/", "Lorg/apache/http/"],
    "sink.sms":          ["sendTextMessage", "sendMultipartTextMessage"],
    "sink.webview":      ["setJavaScriptEnabled", "addJavascriptInterface", "loadUrl",
                          "loadDataWithBaseURL", "postUrl", "evaluateJavascript"],
    "persist":           ["onStartJob", "setRepeating", "setExactAndAllowWhileIdle",
                          "START_STICKY", "BOOT_COMPLETED"],
    "dyn.load":          ["java/lang/DexClassLoader", "java/lang/InMemoryDexClassLoader",
                          "java/lang/Runtime;", "java/lang/ProcessBuilder"],
    "evade":             ["isDebuggerConnected", "test-keys", "/system/bin/su",
                          "/system/xbin/su", "goldfish", "ranchu", "genymotion", "qemu",
                          "XposedBridge", "com.topjohnwu"],
}
COLLECT_PREFIX = "collect."
SINK_PREFIX = "sink."
_RES = {c: re.compile("|".join(map(re.escape, pats))) for c, pats in CATEGORIES.items()}

# common ad/analytics SDK prefixes — collect by design; annotate, don't hide
BENIGN_PREFIXES = ("com/google", "androidx", "android/support", "com/android", "com/facebook",
                   "com/unity3d", "com/applovin", "com/vungle", "com/mopub", "com/ironsource",
                   "com/mbridge", "com/appsflyer", "com/adjust", "com/airbridge", "io/branch",
                   "com/braze", "com/amplitude", "com/crashlytics", "com/kakao", "com/naver",
                   "com/linecorp", "com/igaw", "com/adbrix", "com/cauly", "com/tnkfactory",
                   "com/tencent", "com/unity", "com/bumptech", "com/byappsoft", "com/fsn",
                   # identified in KR app sweeps 2026-09 (commercial ad/mediation/analytics)
                   "com/inmobi", "net/pubnative", "com/chartboost", "com/amazon/device",
                   "com/amazon/aps", "com/nps/adiscope", "com/smaato", "com/fyber",
                   "com/pubmatic", "com/criteo", "com/tapjoy", "com/ogury", "com/bykv",
                   "io/flutter", "com/safedk", "com/apm/insight", "com/bytedance",
                   "com/pgl")

ORG_PREFIXES = ("com", "org", "net", "kr", "jp", "io", "de", "uk", "cn")

def root_of(path: str, depth: int) -> str:
    pkg = path.rsplit("/", 1)[0]
    parts = pkg.split("/")
    if not parts or pkg == "(default)":
        return "(default)"
    if parts[0] in ORG_PREFIXES:
        return "/".join(parts[:depth])
    return parts[0]

def shape(cats: set[str], min_collectors: int) -> bool:
    n_collect = sum(1 for c in cats if c.startswith(COLLECT_PREFIX))
    n_sink = sum(1 for c in cats if c.startswith(SINK_PREFIX))
    return n_collect >= min_collectors and n_sink >= 1

def sweep(jar: str, min_collectors: int):
    cats: dict[str, set[str]] = defaultdict(set)   # root -> categories (depth 3)
    cats4: dict[str, set[str]] = defaultdict(set)  # root -> categories (depth 4, com/* only)
    cls: dict[str, int] = defaultdict(int)         # root -> class count (same depth as key)
    n_cls = 0
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if not name.endswith(".class"):
                continue
            n_cls += 1
            s = z.read(name).decode("latin-1")
            r3 = root_of(name, 3)
            cls[r3] += 1
            for cat, rx in _RES.items():
                if rx.search(s):
                    cats[r3].add(cat)
                    r4 = root_of(name, 4)
                    cats4[r4].add(cat)
                    cls[r4] += 1
    # flag at depth 4 first (a 4-segment SDK root must not be split off its helpers),
    # then depth-3 roots whose shape isn't already covered by a flagged child
    flagged: list[tuple[str, set[str], int]] = []
    for root in sorted(cats4):
        if shape(cats4[root], min_collectors):
            flagged.append((root, cats4[root], cls[root]))
    for root in sorted(cats):
        if any(f[0].startswith(root + "/") or f[0] == root for f in flagged):
            continue
        if shape(cats[root], min_collectors):
            flagged.append((root, cats[root], cls[root]))
    flagged.sort(key=lambda t: (-len(t[1]), t[0]))
    print(f"== behavior-sweep {jar}: {n_cls} classes, {len(cats)} roots ==")
    for root, fcats, nroot in flagged:
        mark = "~FLAG" if root.startswith(BENIGN_PREFIXES) else "FLAG "
        print(f"{mark} {len(fcats):>2}cat {nroot:>4}cls  {root}  [{' '.join(sorted(fcats))}]")
    shown = {f[0] for f in flagged}
    others = sorted(((r, c) for r, c in cats.items()
                     if r not in shown and len(c) >= 3),
                    key=lambda t: (-len(t[1]), t[0]))
    if others:
        print("-- runners-up (>=3 categories, no sink shape):")
        for root, ocats in others[:12]:
            print(f"        {len(ocats):>2}cat  {root}  [{' '.join(sorted(ocats))}]")
    carve = [r for r, _, _ in flagged if not r.startswith(BENIGN_PREFIXES)]
    if carve:
        print(f"carve candidates (SKILL.md Method): {' '.join(carve)}")
    return flagged

def main() -> None:
    args = sys.argv[1:]
    min_collectors = 2
    if "--min-collectors" in args:
        i = args.index("--min-collectors")
        min_collectors = int(args[i + 1])
        del args[i:i + 2]
    if not args:
        raise SystemExit(__doc__)
    any_flag = False
    for jar in args:
        if sweep(jar, min_collectors):
            any_flag = True
    sys.exit(0 if any_flag else 1)

if __name__ == "__main__":
    main()
