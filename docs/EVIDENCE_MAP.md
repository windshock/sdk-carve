# Evidence map

All entries below are static observations from DEX/JAR-derived Java unless stated
otherwise. Provenance is therefore `binary-confirmed`, not `runtime-confirmed`.

| Claim | Evidence |
|---|---|
| Sample package and version | `corpus/decompiled/jadx/resources/AndroidManifest.xml:1` |
| Launcher activity | `corpus/decompiled/jadx/resources/AndroidManifest.xml:283` |
| SMARTLB background service in separate process | `corpus/decompiled/jadx/resources/AndroidManifest.xml:1776` |
| TMAP search-history integration | `corpus/decompiled/jadx/sources/com/skt/tmap/util/MolocoManager.java:1082` |
| SDK version, media ID, and initialization | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/op/SMARTLB.java:23` |
| Persistent JobScheduler registration | `corpus/decompiled/jadx/sources/dg/a.java:58` |
| Advertising base URL `kialant.com` | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/nepkt/RestClient.java:12` |
| Advertising request fields | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/a.java:144` |
| Data/config base URL `bhuroid.com` | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/nepkt/nepkt_hrnRzCx.java:36` |
| Data/config Retrofit endpoints | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/nepkt/nepkt_hrnAz.java:12` |
| Advertising ID and Android ID access | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/b.java:23` |
| Installed application enumeration | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/c.java:160` |
| Wi-Fi hardware address enumeration | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/c.java:78` |
| Bluetooth scanning and bonded devices | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/d.java:61` |
| App/environment collection upload | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/wepkr/wepkr_luhFzJx.java:1055` |
| Device registration and remote-config fetch | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/wepkr/wepkr_luhFzJx.java:1110` |
| Server-controlled collection flags | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/wepkr/wepkr_luhFzJx.java:500` |
| Server response converted to ad payload | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/wepkr/wepkr_luhFzJx.java:586` |
| HTML loaded into custom WebView | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/c/k.java:76` |
| Background WebView lifecycle | `corpus/decompiled/jadx/sources/com/smart/sklb/edge/wepkr/wepkr_luhFzJx.java:643` |

## Important trust boundaries

1. TMAP host policy to third-party SDK initialization.
2. SDK-local identifiers and sensor/package observations to remote Retrofit payloads.
3. Remote configuration to locally enabled collection and advertising behavior.
4. Remote HTML to WebView execution inside the application process.

## Known evidence gaps

- The original APK and its hash are absent.
- No packet capture or emulator/device execution is present.
- Some decompiled methods are incomplete or syntactically invalid.
- The historical CodeQL databases never finalized.
