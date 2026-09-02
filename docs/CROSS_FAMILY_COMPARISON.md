# Cross-family anti-analysis comparison

Normalized `sdk-carve` rows for families analyzed so far (PLAN Phase C). Rows are added as
samples are acquired (Phase B). Every cell is `binary-confirmed` from the noted sample
unless marked otherwise.

| field | **Goldoson / SMARTLB** | **SpinOk** |
|---|---|---|
| sample(s) | 11 McAfee-listed apps (local corpus) | `3745e0fb…402cf17` VicTube_v1.1.2 (MalwareBazaar, sig SpinOK) |
| sdk_package | `com/<a>/<b>/<c>` renamed per app (TMAP `com.smart.sklb.edge`) | `com.spin.ok(.gp)` |
| sdk_classes | ~117–295 carved | ~121 carved |
| entrypoint | JobService/thread — `SMARTLB.smartInit` | `com.spin.ok.gp.receiver.SpinReceiver`, `…activity.WebActivity` |
| c2 / endpoint | Retrofit → `bhuroid.com` etc. (collection/config) + `kialant.com` (ad) | WebView → `d3hdbjtb1686tn.cloudfront.net/gpsdk.html` |
| installed_apps | yes — collected **and** used for the guard blocklist | `getInstalledPackages` (enumeration) |
| hidden_webview | yes — `loadData/loadUrl` click path | WebView reward mini-games (`gpsdk.html`) |
| crypto | **AES/CBC/PKCS5**, hardcoded key `aoKoVu…`, zero IV | **AES/GCM/NoPadding** (`com.spin.ok.gp.code`) |
| **anti_analysis_apps** | **5 packet-capture apps, AES-encrypted blocklist, abort-on-present** | **none in the SpinOk SDK** |
| anti_emulator / sensor / debug | not observed in the SDK | **not in the SpinOk SDK** — sensor/emulator/debugger checks are carried by co-bundled ad networks (maticoo, applovin, unity3d, mbridge, ironsource, pubnative) |

## Finding

At the **code** level the two families' anti-analysis differ: Goldoson uses a targeted,
hardcoded, AES/CBC-encrypted **packet-capture-app blocklist**; the SpinOk SDK in this sample
has **no dedicated analysis-tool guard** and uses a different AES mode (GCM). The
"sensor-based sandbox detection" often attributed to SpinOk is, in this build, contributed
by the **bundled ad-network SDKs**, not the SpinOk marketing SDK itself.

This supports the reference docs' framing: **technique lineage, not shared code/authorship.**
Goldoson's installed-packet-capture-app detection remains distinctive and, so far, unmatched
in the compared families — reinforcing it as the strongest candidate for a dedicated
code-lineage reverse-search (needs AndroZoo, PLAN Phase B/B1).

## Limits

One SpinOk sample/version. Konfety, MobiDash, Invisible Adware, and Necro were **not on
MalwareBazaar** (`hash_not_found`) and need AndroZoo (pending API key). Ad-network
attribution above is by package name in this APK, not per-SDK-version audit.
