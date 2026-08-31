# Track 3 — Goldoson/SMARTLB dataflow model (AI-native trace)

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Method: Direct read of the full `com.smart.sklb.edge` + `bg`/`cg`/`dg` subgraph
(~59 files, <6k LOC), obfuscated-name resolution, and bytecode cross-check
(`javap` over `artifacts/extracted/dex2jar-classes/`) for the two decompile-failed
methods. Evidence labels per `AGENTS.md`: `binary-confirmed` = visible in DEX/JAR
code; `not-confirmed` = requires runtime.

All line references are to `corpus/decompiled/jadx/sources/` unless noted.

---

## 1. One-paragraph summary

The embedded SMARTLB/Goldoson SDK registers a **persistent, reboot-surviving
background `JobService`** (`wepkr_luhFzJx`, job id `159294`, separate process
`:smartlbp_dv`). On each run it fetches **server-controlled configuration** from
`bhuroid.com`, and — when the server flags allow — collects **device identifiers,
the list of installed launchable apps (with add/delete diff over time), precise GPS
location, nearby and connected Wi‑Fi, and Bluetooth (bonded + BLE scan) observations**,
then uploads them to `bhuroid.com` via `putCol`. Separately it retrieves an HTML
ad payload and **loads it into a JavaScript‑enabled WebView created from the
background service, not attached to any visible Activity**, waits ~3 s, and destroys
it. A foreground banner path (`EdgeView`) fetches image/click URLs from `kialant.com`.
All of the above is `binary-confirmed` as a static capability; whether a given backend
returned an active collection/ads payload on a given date is `not-confirmed`.

## 2. Component map (obfuscated name → role)

| Symbol | Role | Key evidence |
|---|---|---|
| `op/SMARTLB` | Public API: `EdgeView()`, `smartInit()`, `smartDriving()` | `op/SMARTLB.java:36,55` |
| `wepkr/wepkr_luhFzJx` | Background `JobService` orchestrator (collect + config + WebView) | `wepkr/wepkr_luhFzJx.java:53` |
| `dg/a` | JobScheduler registration of job `159294`, `setPersisted(true)` | `dg/a.java:58,64` |
| `cg/b` | Encrypted `SharedPreferences` store (identifiers, config, buffers) | referenced throughout |
| `c/b` | Ad ID + Android‑ID‑derived UUID acquisition | `c/b.java:25,64,69` |
| `c/c` | Installed-app enumeration/diff, MAC address, app-usage metric, guard, WebView dir | `c/c.java` |
| `c/d` | Bluetooth: bonded devices + BLE scan | `c/d.java:101,112` |
| `c/g` | GPS via FusedLocationProvider, HIGH_ACCURACY, 2 s interval | `c/g.java:27,42,112` |
| `c/j` | Wi‑Fi: connected info + scan results | `c/j.java:41,65,80` |
| `c/i` | Transforms/env: GZIP+Base64, HmacMD5, carrier, timezone, battery, net | `c/i.java` |
| `c/e` | AES/CBC decrypt (hardcoded key) for guard package names | `c/e.java:14` |
| `c/k` | Custom JS‑enabled `WebView` subclass; `loadData(html)` | `c/k.java:76,86` |
| `c/a` | Foreground banner ad: `kialant.com` → image/click render | `c/a.java:144,167` |
| `nepkt/nepkt_hrnRzCx` | Retrofit client, `baseUrl=https://bhuroid.com` | `nepkt/nepkt_hrnRzCx.java:39` |
| `nepkt/nepkt_hrnAz` | Retrofit interface: `userJoin/getBConfig/isRunable/putCol/getPdata` | `nepkt/nepkt_hrnAz.java:12` |
| `nepkt/RestClient`+`HttpInterface` | Retrofit client, `baseUrl=https://kialant.com` | `nepkt/RestClient.java:18` |
| `bg/a` | Holds server HTML ad payload (`getPdata` response) → `.a()` | used at `wepkr_luhFzJx.java:676` |
| `bg/b` | Parsed remote config (intervals/thresholds) | `wepkr_luhFzJx.java:452` |

## 3. Trigger / entry points  (`binary-confirmed`)

1. Host app `MolocoManager` (search-history ad path) → `SMARTLB.EdgeView()` and
   `SMARTLB.smartInit()` (`docs/EVIDENCE_MAP.md`; `MolocoManager.java:1082`).
2. `smartInit()` → thread → sets `media_idx=367`, `service_start_time`, then
   `dg.a.d()` schedules persistent job `159294` (`op/SMARTLB.java:26-31`, `dg/a.java:64`).
3. `onStartJob` → worker threads → `i0()` → collection orchestrator `g` runnable
   (`wepkr_luhFzJx.java:1315,1310,309`).

## 4. Data sources — what is collected  (`binary-confirmed`)

| Source data | API used | Evidence |
|---|---|---|
| Google Advertising ID | `AdvertisingIdClient.getAdvertisingIdInfo()` | `c/b.java:25` |
| App UUID | `Settings.Secure "android_id"` → `UUID.nameUUIDFromBytes` | `c/b.java:64,69` |
| Wi‑Fi/P2P MAC | `NetworkInterface.getHardwareAddress()` (`wlan0`,`p2p0`) | `c/c.java:82`; used `wepkr_luhFzJx.java:1114,1122` |
| Installed launchable non‑system apps + labels | `PackageManager.getInstalledApplications(128)` + `getLaunchIntentForPackage` | `c/c.java:163,178` |
| Installed-app **diff** (added/deleted `status`) | same, compared to stored `app_data_log` | `c.c.d()` bytecode: `setStatus`, `setSystem`, `setPreload` (decompile-failed; confirmed via `javap`) |
| Precise GPS location (lat/long/accuracy/speed/time) | `FusedLocationProviderClient`, priority 100 | `c/g.java:27,42` |
| Connected Wi‑Fi (IP, SSID, BSSID, RSSI) | `WifiManager.getConnectionInfo()` | `c/j.java:65-67` |
| Nearby Wi‑Fi scan (SSID, BSSID, level) | `WifiManager.startScan()` → `getScanResults()` | `c/j.java:80,41`; filtered `wepkr_luhFzJx.java:175-189` |
| Bonded Bluetooth devices | `BluetoothAdapter.getBondedDevices()` | `c/d.java:101` |
| Nearby BLE devices (address, rssi) | `BluetoothLeScanner.startScan()` → `onScanResult` | `c/d.java:112`; `wepkr_luhFzJx.java:218-227` |
| Carrier / telecom | `TelephonyManager.getNetworkOperatorName()` → SK/KT/LG | `c/i.java:89` |
| Timezone, auto-time, battery/charging, SIM, net type | `TimeZone`, `Settings.Global auto_time`, battery intent, `TelephonyManager`, `ConnectivityManager` | `c/i.java:108,112,120`; `wepkr_luhFzJx.java:1072` |
| App-usage metric | sum over server-provided `ps_list` of matching installed pkgs | `c/c.java:43-76` |

Manifest backs this: `ACCESS_FINE/COARSE_LOCATION`, `BLUETOOTH*`,
`BLUETOOTH_SCAN/CONNECT`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`,
`READ_PHONE_STATE`, `RECEIVE_BOOT_COMPLETED`, `REQUEST_COMPANION_RUN_IN_BACKGROUND`,
`KILL_BACKGROUND_PROCESSES`, `REQUEST_DELETE_PACKAGES`
(`corpus/decompiled/jadx/resources/AndroidManifest.xml`).
Note: `QUERY_ALL_PACKAGES` is **absent**, which on target SDK 33 limits
`getInstalledApplications` visibility at runtime — the code attempts full enumeration
regardless (`not-confirmed` at runtime).

## 5. Transforms  (`binary-confirmed`)

- `c/i.c()` — installed-app JSON → **GZIP + Base64** (compression, not confidentiality). `c/i.java:36`
- `c/i.d(mac, "9W2zr4UU9S")` — MAC → **HmacMD5** keyed hash (stable pseudo-identifier). `c/i.java:46`
- `c/e.a()` — **AES/CBC/PKCS5** decrypt, hardcoded key `aoKoVu#...!Oz`, zero IV — used only to decrypt guard package names. `c/e.java:14`
- Server-adjusted timestamps via `time_gap_from_server` (`c/i.b()`). `c/i.java:24`

## 6. Sinks  (`binary-confirmed`)

| Sink | Endpoint / API | Payload | Evidence |
|---|---|---|---|
| `userJoin` (register) | `POST bhuroid.com/a8e6…` | media_idx, adid, uuid, carrier, HmacMD5(wlan0), HmacMD5(p2p0), app-usage | `nepkt_hrnAz.java:25`; `wepkr_luhFzJx.java:1114` |
| `getBConfig` (config) | `PUT bhuroid.com/a8e6…/{user_idx}` | same body | `nepkt_hrnAz.java:13`; `wepkr_luhFzJx.java:1122` |
| `isRunable` (gate) | `GET bhuroid.com/aa01…` | user_idx, media_idx, adid | `nepkt_hrnAz.java:19`; `wepkr_luhFzJx.java:416` |
| **`putCol` (collection upload)** | `POST bhuroid.com/46c7…` | adid, user_idx, media_idx, uuid, carrier, app-usage, **collection records** (apps, wifi, bt, location, tz, timestamps) | `nepkt_hrnAz.java:22`; `wepkr_luhFzJx.java:977,1075`; FG assembly in `l.b.run()` bytecode |
| `getPdata` (ad HTML) | `POST bhuroid.com/e211…` | adid, user_idx, media_idx, uuid, carrier, app-usage, **gzip’d installed-app list**, wifi flag | `nepkt_hrnAz.java:16`; `wepkr_luhFzJx.java:1278` |
| **Hidden WebView** | `c/k.loadData(html)` | server `n-premiums` HTML, JS enabled | `c/k.java:80`; `wepkr_luhFzJx.java:676` |
| Foreground banner | `GET kialant.com/request` → image/click | adid, model, OS, carrier, media/user/sdk idx | `c/a.java:167`; `RestClient.java:18` |

## 7. End-to-end dataflow (source → transform → sink)

```
[Ad ID]───────────────┐
[Android-ID→UUID]──────┤
[wlan0/p2p0 MAC]─HmacMD5┤
[carrier]──────────────┼─▶ userJoin / getBConfig ─▶ POST/PUT bhuroid.com  (register + pull server config)
                       │
[installed apps+labels]┐│
  └─(diff over time)   ││
[GPS lat/long/acc/spd] ││
[Wi-Fi conn + scan]    │├─▶ putCol(nepkt_hrnRzBxC) ─▶ POST bhuroid.com/46c7…  ★ primary exfiltration
[Bluetooth bonded+BLE] ││        gated by remote flags collect_enable / collect_fg_enable
[tz, auto-time, ts]    ┘│
                        │
[installed apps]─gzip───┴─▶ getPdata(nepkt_hrnRzPx) ─▶ POST bhuroid.com/e211… ─▶ HTML "n-premiums"
                                                             │
                                                             ▼
                                        c/k JS-enabled WebView.loadData(html)  ★ hidden execution
                                        (created in :smartlbp_dv service, ~3s, then destroy)
```

## 8. Server-controlled behavior  (`binary-confirmed`)

`getBConfig` response (`wepkr_luhFzJx.java:507-537`) writes prefs that gate everything:
`ads_enable`, `collect_enable`, `collect_fg_enable`, `collect_percentage`,
`ads_cpi_display_percentage`, intervals (`dispatch_running_interval`,
`collect_send_interval`, `collect_fg_interval`, `ads_cpi_update_interval`),
limits/counts (`collect_limit_count`, `collect_push_count`, `collect_clear_count`,
FG variants), `service_list`, `ps_list`. So the *capabilities* are in the binary but
each is switch-gated by the backend — collection/ads run only when the server enables
them (`ads_enable`/`collect_*_enable != "N"`; checked at `:1154,1269,938,1057`).

## 9. Guard / anti-analysis  (`binary-confirmed`)

`c/c.l()` decrypts 5 hardcoded AES-encrypted package names (`c/e.a()`) and, if any is
installed, **aborts collection/ads** (`c/c.java:196-206`; short-circuits at
`wepkr_luhFzJx.java:406,934,1258`). Also `L()` only proceeds when specific host
services are running (`service_list`, default `TBTpopUpService,TmapRgService,MqttService`)
— i.e., collection is tied to the host being active (`wepkr_luhFzJx.java:1126-1144`).

The 5 guard package names, decrypted with the hardcoded key via `c/e.a()`
(`binary-confirmed`), are all **network/packet-capture inspection tools**:

- `app.greyshirts.sslcapture` (SSL Capture)
- `com.ddm.iptools` (IP Tools)
- `com.myprog.netscan` (Network Scanner)
- `com.myprog.netutils` (Net Utils)
- `jp.co.taosoftware.android.packetcapture` (tPacketCapture)

So the SDK deliberately **aborts collection/ads when a traffic-inspection tool is
present** — an explicit anti-analysis/evasion measure against researchers observing
its exfiltration, consistent with Goldoson's documented behavior.

## 10. Bytecode cross-check of decompile-failed methods

Two target methods were `Method not decompiled` in JADX; `javap` over the class tree
confirms their behavior (so the gap did **not** block analysis):

- `c.c.d(Context)` — builds `nepkt_hrnRzAxI(pkg,label)` from
  `getInstalledApplications` + `getLaunchIntentForPackage`, sets `preload/system/status`
  → **installed-app diff with add/delete status** (`javap` shows `setStatus/setSystem/setPreload`).
- `wepkr_luhFzJx$l$b.run()` — assembles `nepkt_hrnRzLxI` (location lat/long/accuracy),
  `nepkt_hrnRzWxI` (wifi bssid), `nepkt_hrnRzBxI` (bluetooth `getAddress`),
  reads prefs `last_location`/`last_scan_wifi_bssid`, then
  `nepkt_hrnRzCx.getApi().putCol(new nepkt_hrnRzBxC(...))` → **FG collection upload
  including GPS + Wi‑Fi + Bluetooth**.

## 11. Trust boundaries (matches `docs/EVIDENCE_MAP.md`)

1. Host policy → third-party SDK init.
2. On-device identifiers/sensors → remote Retrofit payloads (`bhuroid.com`). ★
3. Remote config → locally enabled collection/ads.
4. Remote HTML → WebView JS execution inside the app process. ★

## 12. Confidence & gaps

- `binary-confirmed`: all sources, transforms, sinks, endpoints, the persistent job,
  the server-gated flags, and the hidden JS WebView path.
- `not-confirmed` (needs Track 4 runtime, isolated): whether the live backend returns
  active `collect_*`/`ads_enable` payloads or non-empty `n-premiums` HTML for a given
  device/date; runtime effect of `QUERY_ALL_PACKAGES` absence; the 5 guard package names.
- Next: Track 1 (scoped `jimple2cpg`) to tool-verify the source→`putCol`/`loadData`
  taint paths; optionally decrypt the guard constants with `c/e.a()`.
