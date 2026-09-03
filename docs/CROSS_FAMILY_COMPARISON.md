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

- **ZIP tamper to break static tools (not real compression):** every entry has a **fake
  "encrypted" flag** (GP bit 0), and `AndroidManifest.xml` **falsely declares method `0x0C`
  (BZIP2) over data that is actually STORED AXML** (with lying sizes). Android's lenient
  loader installs it; `aapt`/`apktool` call it "corrupt" (all 5). Same SoumniBot technique.
- **Decoy `classes.dex`** (7–8 KB): mostly empty stubs. Only `GCw`+`IEk` are real — `IEk` is a
  `java.util.Random`-XOR **string-deobfuscator**; `GCw` uses **reflection** + a
  `ContentProvider` to load the hidden payload.
- **Packed ~2.2 MB `assets/<numeric>` payload:** DEFLATE (behind the fake enc flag) →
  **XOR with `java.util.Random(asset_name + 0xFFFF)`** → inner ZIP → real `classes.dex`.

**Resolved (not a dead end):** the [`pre-carve`](PRE_CARVE.md) stage recovers it fully and
statically — `apk-normalize.py` repairs the ZIP (→ evil-twin identity
`com.herocraft…catchthecandy`, AppLovin manifest) and `konfety-unpack.py` decrypts the asset.
Real payload (all 5, identical): **6,777-class second stage**, carved via a scoped CPG.
Ad stack InMobi + `com.adcommercial`/`com.gnet`/`com.nextg`; **install-referrer gating**;
bundled **LSPosed**; C2 `api.jetengine.be`, `one.upyourphone.me`, `push.razkondronging.com`,
`ssp.atswe.xyz`. Fraud engine = **MobiDash-class**: a **1×1-px `VirtualDisplay`** phantom
viewport renders the ad WebView invisibly (`com.adcommercial.utils.xOnUc`) with synthetic
`MotionEvent` clicks (`svmmk.hg.ehcG`) — "real WebView, fake finger", both reachable from
entry. No in-code emulator/root/packet-capture guard — Konfety's evasion is the packer, its
fraud is the click engine. Full map: [`PRE_CARVE.md`](PRE_CARVE.md) §3.

## MobiDash — parasite loader + SQLCipher payload (Jamf sample `c64db66f…`)

Same *architecture* as Konfety, confirming a shared **loader → encrypted-payload → in-memory
DexClassLoader** pattern (not shared code). Carved the loader from the primary dex; the fraud
engine itself is in the encrypted DB (Jamf-consistent, so absent from the primary dex — no
`Proxy.NO_PROXY`/`VirtualDisplay`/C2 there).

- Host parasitized into `com.stwdi.denhonol.vacbe.jdhcc`; ad mediation IronSource / Unity /
  AppLovin; storage Realm + `net.sqlcipher`.
- **Loader `…jdhcc.mHwymQ`:** key = `digest(getPackageInfo(pkg, GET_SIGNATURES).signatures[0])`
  (**APK signing certificate**) → `SQLiteDatabase.openOrCreateDatabase("jdhcc.db", key)`
  (SQLCipher) → `InMemoryDexClassLoader(...).loadClass("…jdhcc.jdhcc.ftV0BV").newInstance(ctx)`.
- Payload container: **`assets/jdhcc.db`** (3.7 MB SQLCipher DB) vs Konfety's XOR-packed asset.

| | Konfety (`GCw`/`IEk`) | MobiDash (`mHwymQ`) |
|---|---|---|
| payload container | packed `assets/<numeric>` | `assets/jdhcc.db` (SQLCipher) |
| key source | `Random(asset_name + 0xFFFF)` | digest of APK signing cert (`signatures[0]`) |
| decrypt | XOR keystream | SQLCipher `openOrCreateDatabase` |
| layers | 1 | 3 (SQLCipher → bootstrap → XOR modules) |
| load | reflect into `dexElements` | `InMemoryDexClassLoader` → `ftV0BV` → modules |

**Fully unpacked statically** ([`../.claude/skills/sdk-carve/scripts/mobidash-unpack.py`](../.claude/skills/sdk-carve/scripts/mobidash-unpack.py),
verified — no runtime): cert-derived passphrase `794143205` opens the DB (SQLCipher 4);
table `cmnFdTEbL` holds a 7 KB **bootstrap DEX** (`ftV0BV`) + 5 **XOR-encrypted module jars**
(`ext`/`irs`/`apl`/`uni`/`dat`; XOR key = first 10 bytes of each blob, skip 8, 64 KB-chunked).
The bootstrap adds **emulator detection** (`Build.MODEL` vs `nexus 5x`/`OnePlus8Pro`) and a
**hidden-API bypass** (`VMRuntime.setHiddenApiExemptions`).

The recovered **`ext` module (3,496 classes)** is the fraud engine — every Jamf signature,
now code-confirmed in `com.stwdi.denhonol…`:
- **phantom viewport** `createVirtualDisplay`/`Presentation` (`HqJz25`/`NkgMB0`/`jvByHu`)
- **synthetic `MotionEvent` touch** (`uo1vHa`/…)
- **`Proxy.NO_PROXY`** anti-mitm (`uVm228`/…) + a **2,056-class Netty** residential-proxy stack
- `irs`=IronSource (1,834), `apl`=AppLovin (2,732) ad modules.

**Convergence:** Konfety and MobiDash independently arrive at the **same phantom-viewport +
synthetic-touch click-fraud** engine, both reachable only after statically peeling their
loaders. Different packaging (XOR asset vs SQLCipher+XOR modules), same fraud endgame —
technique convergence, and both fully recoverable offline because the key material
(asset-name / in-APK signing cert) never leaves the sample.

## Anti-analysis technique, by layer

| Family | Anti-analysis layer | Mechanism |
|---|---|---|
| **Goldoson** | in-code, runtime | AES/CBC-encrypted **packet-capture-app blocklist** → abort |
| **SpinOk** | (SDK: none) | sensor/emulator checks live in **co-bundled ad networks**, not the SpinOk SDK |
| **Konfety** | packaging + loader | fake-method/fake-enc **ZIP tamper** + decoy dex + `java.util.Random`-XOR **packed asset** (install-referrer gating in payload) |
| **MobiDash** | loader + encrypted DB | primary-dex loader → **SQLCipher `jdhcc.db`** keyed on the **signing cert** → `InMemoryDexClassLoader` fraud engine |

Four samples, four branches → reinforces **technique lineage, not shared code**. Goldoson's
dedicated analysis-tool blocklist stays unique; Konfety and MobiDash independently converge on
the **loader → encrypted-payload → in-memory-DexClassLoader** shape (XOR-packed asset vs
SQLCipher DB), and both payloads reach the same **phantom-viewport click-fraud** endgame.

## Limits

One SpinOk version; 5 Konfety samples (payload fully carved); 1 MobiDash (Jamf `c64db66f…`
via Triage — **fully unpacked**: SQLCipher DB + XOR modules → fraud engine, statically).
Invisible Adware and Necro are on none of MalwareBazaar / Hybrid Analysis / our Triage
exports → need AndroZoo (academic-gated). Ad-network attribution for SpinOk is by package
name, not per-version audit.
