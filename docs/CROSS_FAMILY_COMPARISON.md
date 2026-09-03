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

## Konfety / CaramelAds — a third, packaging-layer branch (5 samples)

Source: Hybrid Analysis (all 5 Zimperium hashes; sha256-verified). Konfety does **not**
use an in-code environment guard at all — its anti-analysis is at the **APK packaging /
dynamic-loading layer**, and it defeats static bytecode carving:

- **Corrupted manifest to break static tools:** `AndroidManifest.xml` is **BZip2**-compressed
  (a method Android tolerates but the APK spec doesn't sanction) → `aapt`/`apktool` report
  "corrupt" on all 5. Installable, but static-analysis-hostile.
- **Decoy `classes.dex`** (7–8 KB, 7–14 classes): mostly empty stubs (`class K { void GCw(){} }`).
  Only `GCw`+`IEk` are real — `IEk` is a char-wise **string-deobfuscator**, `GCw` uses
  **reflection** (`Class.forName(IEk(...))` → `newInstance`) and a `ContentProvider`
  auto-start to load the hidden payload.
- **Packed ~2.2 MB `assets/<numeric>` payload** carrying the real SDK; the ZIP entry is
  itself tampered (`unzip` size-mismatch; `7z` hangs) — resists extraction.

**Method implication (honest limit):** sdk-carve's JVM track sees only the decoy + loader
stub. Carving Konfety's real SDK needs a runtime/unpack pre-step (drive the loader or
decrypt the asset) before the bytecode pipeline applies — a precondition Konfety
deliberately breaks.

## Anti-analysis technique, by layer

| Family | Anti-analysis layer | Mechanism |
|---|---|---|
| **Goldoson** | in-code, runtime | AES/CBC-encrypted **packet-capture-app blocklist** → abort |
| **SpinOk** | (SDK: none) | sensor/emulator checks live in **co-bundled ad networks**, not the SpinOk SDK |
| **Konfety** | packaging + loader | **BZip2 manifest** + decoy dex + reflectively-loaded **packed asset** |

Three samples, three different branches → reinforces **technique lineage, not shared code**.
Goldoson's dedicated analysis-tool blocklist remains unique among the three.

## Limits

One SpinOk version; 5 Konfety samples (not yet unpacked). MobiDash, Invisible Adware, and
Necro are **not on MalwareBazaar or Hybrid Analysis** (`hash_not_found`) → need AndroZoo
(academic-gated) or another source. Ad-network attribution for SpinOk is by package name,
not per-SDK-version audit.
