# Vendor hardening requests — consolidated (KR SDK triage)

Evidence-backed, vendor-addressable hardening asks distilled from the per-SDK triage reports. Each item
is a **design/hardening** request (none of these are confirmed active exploitation or malware). Findings
are static (decompile + CPG); severities are design-weakness ratings, not exploited-in-the-wild claims.

> **Disclosure note.** This is a draft for coordinated disclosure. Actually contacting a vendor is an
> outbound action requiring explicit sign-off (see ROADMAP E-P3) — this file only prepares the asks.

---

## 1. GPA KOREA — GAD SDK (Syrup adtech)  · `com.github.koreagpa-dev:gad:syrup-0.8.0-rc.12`
**Finding** (GAD_API_RUNTIME_CAPTURE.md, GAD_BSH_SANDBOX_RUN.md): the SDK runs **server-supplied BeanShell
scripts in-process** (`setup`/`prepare2` media-scope bootstrap + `script/entry` campaign lifecycle hooks;
live SDK objects injected as vars before `eval`). The entire channel — endpoints `campaign/{setup,prepare2,
script/entry}`, `type=5` CPS, `x-tdi-client-secret` header — is **absent from all public developer docs**
(README/api-doc/guide_cpa cross-checked). Observed script content was benign, but the channel is
**RCE-by-design**: server (or MITM) integrity = arbitrary code in the host app process.
**Risk class:** server-driven code execution (design). 
**Requested hardening:**
1. **Disclose the script channel** in integrator docs (currently undocumented) so publishers can risk-assess.
2. **Constrain the interpreter**: pin BeanShell ≥ 2.0b6 (CVE-2016-2510 class), or migrate off a
   Turing-complete server-script channel to a declarative/allowlisted command set.
3. **Script integrity**: sign server scripts (publisher-verifiable) + pin the delivery endpoint (cert
   pinning) so a MITM cannot substitute the eval payload.
4. **Least privilege**: stop injecting live SDK/app objects into the script scope; expose a narrow, audited API.
5. Document `type=5` (CPS) and the `x-tdi-client-secret` header semantics.

## 2. TNK Factory — TNK/Adiscope rewarded SDK (`rwd`)  · v7.31.3 / v8.09.32
**Finding** (TNK_FULLPASS.md §2/§4.1): a **custom `ObjectInput` (`e.f`)** deserializes `api3.tnkfactory.com`
responses with a `loadClass`+`newInstance` path gated only by `instanceof Externalizable` — **no class-name
allow-list**, using the **app classloader** (full runtime classpath) and a self-rolled ObjectInput that
**bypasses the JEP-290 filter**. The transport (`SSLFactory` = `SSLContext.init(null,null,null)`) uses
default system-CA trust with **no certificate pinning**; the trust-all `TnkAssert$NullHostNameVerifier`
exists but is confined to self-test (not wired to production). Net: the deser gadget input is guarded only
by the device CA store.
**Risk class:** unsafe deserialization + unpinned transport (design, medium).
**Requested hardening:**
1. **Class-name allow-list** on the custom `ObjectInput` (accept only the SDK's own expected value types).
2. **Drop Java serialization** for a type-safe wire format (protobuf/JSON-with-schema).
3. **Certificate pinning** on `api3.tnkfactory.com` (and the media/cache hosts) — removes the MITM path
   to the deser gadget.
4. **Remove `NullHostNameVerifier`** from shipped code (latent MITM hole if ever wired in).
5. Hygiene: remove the residual **Adiscope `dev` endpoint**, drop the legacy `getDeviceId`/IMEI call, and
   apply v7's string encryption to v8 (v8 ships plaintext).

## 3. Adison (NBT) — AdiSON Offerwall SDK  · v3.16.4 (Syrup-bundled) / v5.4.0
**Finding** (ADISON_SDK_TRIAGE.md §9): no native/identifier attack surface, but the **web→app JS bridge**
(`ui/web/SharedWebViewJsInterface`, ~9 methods) + `AdisonUriParser` expose a low–medium navigation surface:
(a) `openExternal("intent://…")` → **`Intent.parseUri(url, URI_INTENT_SCHEME)` → startActivity** (campaign
landing can craft/fire arbitrary intents; no BROWSABLE gate); (b) `openExternal(url, packageName)` lets web
content set the **target package**; (c) **no destination-domain allow-list** for `adison://inappbrowser?url=`
or http(s) opens (arbitrary pages loaded into the bridge-bearing in-app webview); (d) `copyToClipboard` from
web. (adison-scheme deeplinks *are* host-gated to internal activities — so this is a bounded surface.)
**Risk class:** webview navigation bridge (design, low–medium).
**Requested hardening:**
1. **Destination-domain allow-list** for `open`/`openExternal`/`inappbrowser` http(s) targets.
2. **Constrain the `intent:` scheme**: avoid raw `Intent.parseUri(URI_INTENT_SCHEME)`; apply a
   scheme/component allow-list (and set BROWSABLE/selector filtering).
3. **Reject or validate web-specified `packageName`** in `openExternal(url, packageName)`.
4. Scope `copyToClipboard` (confirm/limit web-initiated clipboard writes).
5. Hygiene: drop the residual **`dev`/apiary-mock** endpoints from `Constants.UrlInfo` in shipped builds.

## 4. Coocon (kr.co.coocon) — SASAPI scraping engine  · in M-STOCK, IBK, 신한, 현대해상
**Finding** (COOCON_SASAPI_TRIAGE.md): the SDK **downloads JavaScript over a socket and executes it
in-process** (`updateScript` → `ScriptManager`/`loadScript` → `ScriptEngine`/`V8ScriptEngine`
`evaluateString`) for financial-site scraping. RCE-by-design, comparable to the GAD channel, running inside
bank/broker apps. Traffic is SEED-encrypted; pinning/endpoint integrity unconfirmed.
**Risk class:** server-driven code execution (design). This is a govern-the-vendor ask for the *host*
banks/brokers as much as for Coocon.
**Requested hardening (Coocon + integrating financial institutions):**
1. **Script integrity + endpoint pinning**: sign the scraping scripts and pin `updateScript`'s server so a
   MITM cannot inject JS into the app process.
2. **Least privilege / scope**: constrain what the server scripts can touch; document the scraped-data scope.
3. Institutions: **govern this as a supply-chain code channel** (vendor server integrity, script signing,
   incident scope) — same class as any server-driven-eval dependency.

---

## Priority for outreach (if authorized)
| Vendor | Severity (design) | Why first |
|---|---|---|
| Coocon + banks | server code-exec, financial | runs in bank/broker processes; broadest blast radius |
| GPA GAD | server code-exec | undocumented RCE-by-design channel across many Syrup-bundled apps |
| TNK | unsafe deser + unpinned | reachable via MITM to a whitelist-less gadget |
| Adison | webview bridge | bounded low–medium; landing-page trust boundary |

Evidence + method for every item: the linked triage report + `packer-detect`/`sdk-carve`/`xshield-reversal`
under `.agents/skills/`. All sample binaries stay local (never committed).
