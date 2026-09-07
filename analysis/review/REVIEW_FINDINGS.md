# Independent-review addendum — SK Planet 4-app malicious-SDK triage (measured)

**Reviewer role.** Independent check of `analysis/reports/{SYRUP,OKCASHBAG}_SDK_TRIAGE.md`,
`SKPLANET_APP_SWEEP.md`. Read-only: no original report/script modified; nothing executed on device.
Two recommended checks from the review were **run** to convert opinion → measurement:

- **#1 encrypted anti-analysis guard** — `research/decrypt_goldoson_blocklist.py` on all 4 apps.
- **#3 quiet-root pass** — `analysis/review/quiet-root-pass.py` on all 4 apps: finds roots that *can*
  exfil (network/webview sink) but carry hidden-collection machinery (reflection / runtime
  crypto+base64 / dynamic loading / non-ASCII "obfuscated identifiers") while showing **few plaintext
  capability APIs** — i.e. the exact blind spot of `behavior-sweep.py` (literal-API-name matching).

dex2jar class counts match the reports exactly (syrup 104,029 / okcb 111,713 / orak 92,120 /
wezuro 60,648) — same samples.

## #1 result — encrypted Goldoson blocklist (packet-capture-app guard)

| app | Goldoson-key blocklist entries decrypted |
|---|---|
| 시럽 | 0 |
| OK캐쉬백 | 0 |
| 오락 | 0 |
| 위주로 | 0 |

**Reading.** Supports the SWEEP's "no packet-capture-app blocklist" statement — now *by the
appropriate check*, not by plaintext absence. **Caveat (scope of the check):** the decryptor tests the
**specific Goldoson AES key**; a blocklist under a *different* key/scheme would not be caught. So this
confirms "no Goldoson-family encrypted guard", not "no anti-analysis guard of any kind."

## #3 result — the "0 unknown roots / all attributed" claim does not hold

`behavior-sweep` is blind to string-obfuscated SDKs (they show ~no plaintext capability APIs, so they
never form a "collect≥2+sink≥1" cluster). The quiet-root pass surfaced **many exfil-capable,
heavily-obfuscated third-party SDKs that the reports do not enumerate**, plus one wrong attribution and
one missed dynamic-execution engine. None are shown to be malicious — they appear to be legitimate
Korean adtech/reward SDKs — **but their presence unassessed contradicts the report's completeness /
attribution claims and leaves their (obfuscated) collection behavior unverified.**

### Headline items (binary-confirmed by class inventory)

1. **Mis-attribution — OK Cashbag `ai/`.** OKCASHBAG report table:
   `` `ai/` | protobuf internals (not a suspicious root) | — ``.
   Actual: **`ai/fairytech/moment/MomentSDK`** — **Fairytech "Moment"**, a third-party cashback/reward
   SDK (1,611 classes; `MomentPush`, `MomentInitProvider`, `addDeviceToken`,
   `ListCashbackResultCallback`; refl≈110, 8 webview sinks, 6 network sinks). **Not protobuf.** An
   un-carved reward SDK that handles device tokens + push + webview in a payments app is exactly a
   privacy-relevant collector — it must be identified and carved, not dismissed.

2. **Missed dynamic-execution engine — Syrup `bsh/`.** 174 classes = **BeanShell**, a full Java
   **script interpreter** (`BSHClassDeclaration`, `BSHAllocationExpression`, `ParserConstants`, …).
   `behavior-sweep`'s `dyn.load` only matches `DexClassLoader`/`InMemoryDexClassLoader`
   (+Runtime/ProcessBuilder) — it **cannot** see a bundled interpreter, which can `eval` arbitrary
   (incl. server-supplied) script. Unmentioned in the report. Bundling may be benign, but an embedded
   interpreter in a payment-adjacent app is a review item and a concrete false-negative-vector example.

3. **Un-enumerated obfuscated exfil-capable SDKs** (present with network/webview sinks; not named in
   the reports; grep confirms none appear):
   - **시럽**: `com/avatye/pointhome` (Avatye PointHome offerwall, OBF≈666, 7 webviews, GAID),
     `com/igaworks/ssp` (IGAWorks SSP, net14/web41), `com/mobwith/*` (MobWith; `imgmodule` refs
     `ContactsContract`), `com/gad/sdk`, `kr/co/touchad/sdk`; R8 roots `ch`,`bsh`,`l5`,`i6`.
   - **OK캐쉬백**: `ai/fairytech/moment` (above), `com/anick/sdk` (AnickSDK; net20/web12/crypto2/GAID),
     `com/avatye/pointhome`, `com/igaworks/ssp`, `com/mobwith/*`.
   - **오락**: `com/mocoplex/adlib` (Mocoplex AdLib; refs `ContactsContract`), `com/tyrads/sdk`
     (Tyrads offerwall), `com/mobwith/httpmodule`; R8 roots `sc`,`ka`,`mh`,`md`,`j2`,`qa`,`a8`.
   - **위주로**: only recognized framework/ad SDKs surfaced — consistent with its report.

4. **Trusted-but-unverified surface.** The recognized ad SDKs are massively string-obfuscated
   (`com/ironsource/adqualitysdk` OBF≈1020, `com/naver/ads` OBF≈905, `com/moloco/sdk/xenoss` ≈600,
   `com/unity3d/ads` ≈540). `behavior-sweep` marks these `~BENIGN` and never carves them. Because
   their capability APIs are obfuscated, "every collector attributed" really means "every **plaintext**
   collector attributed" — the majority of the ad-SDK collection surface was waved through by name.

## Identification pass (measured) — resolves the un-enumerated roots

`analysis/review/endpoint-inventory.py` on each root (hosts + capability refs + ContactsContract
discriminator). Result: the un-enumerated roots are **legitimate Korean adtech / benign libraries**,
not malware — which *strengthens* the negative verdict — but three have **obfuscated endpoints** and
remain data-flow-unverified.

| root (app) | identity | plaintext endpoints | caps | status |
|---|---|---|---|---|
| `com/mobwith/*` (시럽·OK·오락) | MobWith ad SDK | mobwithad.com, mobon.net, coupang, adpiex, nhnace | net/webview/GAID/androidId | legit adtech; **contacts = Glide `StreamLocalUriFetcher` photo-load, bulk=0** |
| `com/igaworks/ssp` (시럽·OK) | IGAWorks **AdPopcorn** SSP (reward, NaverPay) | *.adpopcorn.com (many) | webview×38, GAID×12 | legit adtech (financial reward flows) |
| `com/avatye/pointhome` (시럽·OK) | Avatye PointHome offerwall | avatye.com, mncade.com | webview, GAID, androidId | legit; **hardcoded dev LAN `http://192.168.0.81:3000/` left in prod** (hygiene) |
| `com/anick/sdk` (OK) | Anick / commsad ad SDK | api.anick.io, commsad.com, coupang | net/webview/GAID | legit adtech |
| `kr/co/touchad` (시럽) | RunComm TouchAd | *.ta.runcomm.co.kr | net/webview/GAID | legit adtech |
| `com/mocoplex/adlib` (오락) | Mocoplex AdLib mediation | adlibr.com | net/webview | legit; **contacts = `auil` Universal-Image-Loader photo-load, bulk=0** |
| `md/`, `ka/`, `ch/`, `mh/` (오락·시럽) | Naver VETA ad / MobWith frag / **Logback** / image-loader | veta.naver.com, logback.qos.ch | net/webview | benign libs (R8-renamed) |
| **`ai/fairytech/moment` (OK)** | **Fairytech Moment reward/usage SDK** | **none plaintext (DexGuard string-encrypted)**; protobuf wire (`ai.fairytech.moment.protobuf.*`) | reflect (invoke×92), webview, usage-stats, boot+package receivers | **UNVERIFIED data flow** — see deep-dive |
| **`com/gad/sdk` (시럽)** | unattributed ad SDK ("gad") | **none plaintext (obfuscated)** | net×12, webview×6, GAID, androidId | **UNVERIFIED data flow** |
| **`com/tyrads/sdk` (오락)** | Tyrads offerwall | **none plaintext (obfuscated)** | webview, GAID | **UNVERIFIED data flow** |

**Contacts (all four apps): confirmed benign.** Every `ContactsContract` reference is an image-loader
loading a *contact photo* (`bulk-context=0` in every module) — the performer's READ_CONTACTS
attribution is correct and now independently verified. No bulk contact enumeration anywhere.

**Residual honest risk = 3 obfuscated-endpoint reward SDKs** (Fairytech Moment, `com/gad/sdk`, Tyrads):
device-IDs + usage-stats/webview with endpoints hidden by string-encryption → *what they collect and
where it goes is not statically determinable*. These are the roots where "clean" is least supported and
that warrant a proper carve+CPG or dynamic capture. (Legitimacy plausible — Fairytech/Tyrads are known
reward vendors — but unverified.)

## Carve + CPG of the 3 obfuscated-endpoint SDKs (proper sdk-carve pass)

Each carved → jimple2cpg CPG → Joern source→sink + reachability + decrypt evidence
(`analysis/review/ss-review.sc`).

| SDK (carve) | methods | plaintext collectors | sinks | Cipher `doFinal` | collector→sink reachableBy |
|---|--:|---|---|--:|--:|
| **ai/fairytech (Moment)** | 21,409 | `getId`×1 (`addDeviceToken`) only | net: openConnection×3, connect×2, execute×4; webview: loadUrl×3, evaluateJavascript, loadData | **2** | 0 (degenerate) |
| **com/gad/sdk** | 2,040 | `getId`×59 (ambiguous) | webview loadUrl×4/evalJS/loadData; retrofit `enqueue` | 0 | 0 (degenerate) |
| **com/tyrads** | 826 | `getId`×1 | webview loadUrl + evaluateJavascript | 0 | 0 (degenerate) |

**Interpretation (the key methodological point).** All three have **network and/or WebView exfil
sinks** (Fairytech: full HTTP layer `ai.fairytech.moment.http.*` + `FullWebViewActivity`; gad:
Retrofit + JS-bridge `com.gad.sdk.bridge`; tyrads: WebView offerwall shell). But the **collector API
names and endpoints are string-obfuscated**, so the CPG source set is nearly empty (`getId` only) and
`reachableBy` returns **0 — a *degenerate* zero, not evidence of "no exfil."** This is exactly the trap
to avoid: a name-matching analyzer (Joern or CodeQL) reports 0 flows because it cannot *see* the
sources, not because none exist. Static analysis — including sdk-carve — **cannot resolve these three**;
that is the method's RQ5 failure boundary, demonstrated on live targets.

- **Fairytech Moment = highest residual** (full deep-dive below). Correction to an earlier interim
  note: **there is no Go component** — the `*.golang.org` strings are **protobuf descriptor URLs**
  (`google.golang.org/protobuf/...`); the SDK's wire format is **Protocol Buffers**
  (`ai.fairytech.moment.protobuf.*`), and there is **no Fairytech/Go `.so`** in the APK.
- **gad**: WebView + Retrofit ad SDK; endpoints obfuscated (no in-scope `doFinal` — decrypt likely in a
  shared util outside the carve, or endpoints assembled another way). Standard ad-SDK shape.
- **tyrads**: thin WebView offerwall shell — behavior is server-driven inside the WebView, inherently
  opaque to static regardless of obfuscation.

**Resolution requires dynamic analysis** (instrumented run / TLS-intercepted traffic), which the
project's no-execution / no-domain-contact gate forbids. So for these three the honest end-state is
**"static-unresolved; dynamic analysis recommended"** — not "clean." No malware evidence was found; but
absence cannot be asserted statically for an SDK whose collectors and endpoints are encrypted.

## Fairytech Moment — deep-dive (measured; carve + CPG + manifest)

The one SDK the report actively mislabeled ("`ai/` = protobuf internals, not suspicious") and the most
collection-capable + most opaque component in OK Cashbag. What static *can* establish:

- **Wire format = Protocol Buffers** (`ai.fairytech.moment.protobuf.*`). The `golang.org` strings are
  protobuf-descriptor URLs, **not** a Go binary; no Fairytech `.so` in the APK. (Corrects an interim note.)
- **Obfuscation = SK's app-wide RASP (AppSealing / `com.xshield`), NOT DexGuard and NOT Fairytech's
  own.** *(Corrects an interim "DexGuard-style" label.)* Fairytech's decryptor `ai/fairytech/moment/g`
  ultimately resolves strings through **`com.xshield.dc.ɌȔ̏ʒ(int)`** (a string-vault accessor →
  `m37iIIiiiiiIi(i,7)`), and the vault is **native-backed**: `com/xshield/da` has native methods,
  `com.xshield` calls `System.loadLibrary`, and the APK ships `libdxbase/libprotect/libpglarmor/
  libnms/libeca758.so` (AppSealing/INKA protection libs). `com.xshield` hooks the classloader app-wide
  (`_s(ClassLoader)`) + has RASP telemetry (`ǎˑ͔ʍ(Location/MotionEvent/Context)`). **So every string in
  OK Cashbag — bb8, host code, all SDKs — is encrypted by SK's own protector, not by the SDKs.**
  Collectors are also called **reflectively** (`invoke`×92, `getMethod`×24, `forName`×11).
- **Registered components (manifest):** `MomentInitProvider` (ContentProvider → auto-init at every app
  launch, no explicit host init needed), `BootReceiver` (**BOOT_COMPLETED persistence/autostart**),
  `PackageStateReceiver` (**install/uninstall monitoring** → app-inventory intelligence over time),
  two obfuscated services (`j.attachInfo`, `j.getType`), `FullWebViewActivity`.
- **Capability shape (CPG):** usage-stats + WebView (loadUrl/evaluateJavascript) + HTTP layer
  (`moment/http/*`: openConnection/connect/execute) + device-token handling.
- **Endpoints: not recoverable by proportionate static means — because of SK's own AppSealing RASP,
  not Fairytech.** The string vault is native-backed and runtime-gated (AppSealing decrypts under
  integrity/anti-debug checks). "Unpacking" it statically = reversing a hardened commercial native
  protector (`libdxbase/libprotect/...`), which AppSealing is specifically designed to resist — a large
  native-RE effort, and often the strings only decrypt at runtime on a device passing RASP checks.

**Calibrated read (revised down).** Fairytech's endpoint opacity is an artifact of **SK's app-wide
AppSealing protection**, not SDK evasion — every component is equally encrypted. Its *behaviour shape*
(auto-init + boot persistence + package-state monitoring + usage-stats + protobuf) is
**aggressive-but-category-normal** for a usage/reward SDK (adjoe does the same). **No malware
indicator.** The report's real error was **dismissing the single most-worth-examining SDK as 'protobuf
internals, not suspicious'** — not a missed threat.

**Two obfuscation layers — which one blocks the endpoints (verified).** Fairytech ships its *own*
obfuscation (control-flow + reflective char-decode; 93 classes use its `g` decoder) **and** SK's
AppSealing is layered on top (326 Fairytech classes reference `com.xshield`). But the **endpoint/field
strings specifically resolve through `com.xshield.dc(int)`** (measured: Fairytech's `http/*` classes
fetch strings via ~18 `com.xshield.dc` calls, ~0 own-decoder) — i.e. the *binding* blocker for the
endpoints is **SK's native AppSealing vault**, not the vendor layer. Consequence: the **pre-sealed
build removes exactly that layer** and exposes the endpoints as Fairytech delivered them; any residual
Fairytech-own encoding on those strings is **pure-Java (reflective char-decode) → statically
crackable**, unlike the native AppSealing vault. So the vendor layer *is* a legitimate crack target,
but it is the *soft* one; the *hard* one (AppSealing) is solved by provenance (pre-sealed build), not RE.

**Right way to read the endpoints (proportionate, decisive):** *do not crack SK's own RASP.* This is an
**internal SKP audit of SK's own app** — the security team controls the AppSealing pipeline, so obtain
the **pre-sealed build** (APK/AAB *before* AppSealing) and analyze it statically: all strings
(Fairytech/gad/Tyrads endpoints + collected fields) are plaintext there, recovered in minutes. If only
the sealed build is available, the fallback is **sanctioned dynamic** on an AppSealing-passing device
(hook `com.xshield.dc` string accessors → dumps the whole vault) — but the pre-sealed build is far
cheaper and cleaner.

## The app protector itself (AppSealing / `com.xshield`) is the highest-privilege, least-verifiable component

A point the triage (and my own earlier passes) under-weighted: **the RASP/protector has strictly more
power than any SDK, and is the one component that cannot be cleared statically.** `com.xshield`:
- hooks the **classloader app-wide** (`_s(ClassLoader)`), so it can intercept/rewrite any class load;
- ships **native libraries** (`libdxbase/libprotect/libpglarmor/libnms/libeca758.so`) that hold the
  string vault and run under anti-debug/anti-tamper — **designed to defeat static and dynamic analysis**;
- already has **telemetry hooks touching `Location`, `MotionEvent`, `Context`** (`ǎˑ͔ʍ(...)`).

So a *compromised or malicious* app-protector (or a tainted build of it) is a textbook supply-chain
vector: it could inject collection app-wide and be **invisible by construction**, and — exactly like the
performer's one-line "SK app-protection library, classified lib" — it is **waved through by default**
(the "named ⇒ trusted" trap, at the most privileged layer). "It's the protector, so it's fine" is
**unfalsifiable by static** (the protector defeats static by design) — which means static also cannot
*clear* it. This is a **trust/provenance** question, not a code-reading one.

**Calibration.** AppSealing (INKA Entworks) is a mainstream, legitimate commercial RASP used across
Korean financial apps — base-rate strongly benign. The concern is not "it is malicious" but "it is the
one component whose integrity the whole app rests on, and it was never verified."

**Decisive test = sealed vs pre-sealed diff (the same counterfactual as infected↔clean).** SK controls
the AppSealing pipeline, so obtain the **pre-sealed build** and diff it against the shipped (sealed)
build. *Everything the diff adds is exactly what the protector injected.* Expected delta = the RASP
machinery only (`com.xshield` + the 5 `.so` + the classloader/telemetry hooks). **Any unexpected
collector / endpoint / class in the delta is the finding.** This isolates the protector's contribution
precisely and is the proportionate, falsifiable way to assure the protector layer.

**Provenance checks (supply-chain):** (1) verify the injected `com.xshield` classes + native `.so`
hashes against a **known-good AppSealing baseline** (another SK/enterprise app sealed with the same
version, or INKA-attested artifacts); (2) confirm SK's build pipeline pulls AppSealing **directly from
INKA** at a pinned version (integrity of the sealing step itself); (3) specifically review **what the
RASP telemetry sends** — `ǎˑ͔ʍ(Location)` in a protector is worth confirming (RASP normally needs
MotionEvent for bot-detection; Location is less standard and should be justified).

## Effect on the performer's conclusions

- The **malicious-family screen** (no Goldoson/SpinOk/Konfety/MobiDash/Necro plaintext IOC/anchor; no
  Goldoson encrypted blocklist) **stands** and is now better supported (#1). No evidence of malware was
  found by this review either.
- The **completeness / attribution claims are overstated**: "unknown-root count: 0 — every
  collector+sink cluster attributed to a named first-party or commercial SDK" is contradicted by ≥5
  unenumerated named SDKs + several unattributed R8 roots + one wrong attribution (`ai`) + a missed
  interpreter (`bsh`). The correct claim is a **negative screen over the plaintext-visible surface**,
  not a proof of full attribution.
- The **privacy story is under-reported**: beyond bb8 and Enliple cashkeyboard, OK Cashbag also ships
  **Fairytech Moment** (reward SDK, device-token/push) and **Anick**; all three apps ship
  **Avatye/IGAWorks/MobWith**; 오락 ships **Mocoplex AdLib** touching `ContactsContract`. These are the
  actual attack/privacy surface for an SKP internal audience.

## Recommended corrections to the reports (wording)

- OKCASHBAG table: `ai/` "protobuf internals" → **"ai.fairytech.moment — Fairytech Moment reward SDK
  (device-token/push/webview); un-carved."**
- SYRUP: add `bsh` (BeanShell interpreter) to the inventory + note as a dynamic-exec surface outside
  the `dyn.load` signal.
- SWEEP "unknown-root count: 0 / every cluster attributed" → **"0 unknown *plaintext* clusters;
  string-obfuscated SDKs (Avatye/IGAWorks/MobWith/Fairytech/Anick/Mocoplex/Tyrads) surfaced only by a
  reflection/obfuscation pass and are not individually carve-verified."**
- Keep "no known malicious SDK family" but scope it to plaintext IOC + the specific Goldoson-key guard.

## Remaining gaps this addendum did NOT close (still recommended)

- Carve + inventory the un-enumerated SDKs above (esp. Fairytech Moment, Avatye, MobWith `imgmodule`
  ContactsContract, Mocoplex AdLib ContactsContract) at least to endpoint level.
- Identify the unattributed R8 roots (`ch`,`l5`,`i6`,`sc`,`ka`,`mh`,`md`,`j2`,`qa`,`a8`).
- Complete the deferred mandatory steps (Syrup scope-closure; bb8 carve including `com.skplanet.c3po/*`).
- Provenance: compare 시럽 (mirror) against an official-channel copy before any public "clean" claim.

*Harness: `analysis/review/quiet-root-pass.py` (read-only). Non-ASCII "OBFident" = short constant-pool
identifiers using non-Hangul/CJK non-ASCII letters/marks — a commercial-obfuscation tell, not by itself
malicious.*
