# KR mobile supply-chain — consolidated memo (RASP + server-code channels + adtech)

Decision-maker synthesis of the 2026-09 analysis (per-SDK/per-app detail in the linked reports). Scope:
Korean Android apps carrying NSHC xShield RASP + the third-party SDKs bundled alongside it. Everything
below is **static/CPG evidence** (decompile + jimple2cpg→joern + emulation); severities are
design/supply-chain ratings, **not** claims of active exploitation or malware. Samples stay local.

> **Note.** The SKP-specific xShield assessment is a separate deliverable (`~/Downloads/xshield/`). This
> memo covers the broader fleet + the cross-cutting patterns worth governing.

## The one thing to remember
Multiple widely-installed KR apps (banks, brokers, adtech) ship **server-driven in-process code channels**
— a server can push code (BeanShell/JS) that runs inside the app. None observed doing anything malicious,
but each collapses app security to *the vendor's server + transport integrity*. Two independent instances,
same class as [[gpa-gad-beanshell]]:
1. **GPA GAD** (Syrup adtech) — server **BeanShell** eval. **Binary-confirmed in 3 apps: Syrup, 캐시몽
   (`com.reward.cashmong`), 알바몽 (`com.rainbow.albamong`)** — same `com.gad.sdk` + `bsh.Interpreter` +
   `gad.api.gpakorea.com` + the `campaign/{setup,prepare2,script}` lifecycle. Android-only (iOS SDK ships
   no interpreter — asymmetric).
2. **Coocon SASAPI** — server **JavaScript** (Rhino/V8) scraping engine, in 4 financial apps.
These are **RCE-by-design dependencies**, not bugs. Govern them like any "server can run code in our app"
supply-chain surface: vendor server integrity, script signing, endpoint pinning, least-privilege scope.

## 1. RASP layer — NSHC xShield/DxShield (14 apps)  → XSHIELD_FLEET_SURVEY.md
- 14 KR apps confirmed (engines 6.3.1.85–6.9.20.31); 1 negative (부국증권). Two mgmt servers:
  **`xo.dxshield.com`** = Coocon-heavy brokers (Mirae, IBK); **`xo.fxshield.co.kr`** = shared default (신한,
  HMG apps, 빗썸, L.POINT, 현대캐피탈/해상, 우리, SKP).
- **This variant leaves the app's real dexes PLAINTEXT** (only a loader + config encrypted) — RASP value is
  runtime anti-debug/root/hook + a native string vault, *not* code confidentiality. So the bundled-SDK
  inventory is directly readable; the "protection" is behavioral, not a carve blocker.
- Native string vault statically recoverable (`find_decryptor.py`, per-build auto-located; arm64 incl.
  6.9.20.x). IOCs = root/frida/xposed/magisk detection, remote-control-app blocklist, mirroring/USB-debug.

## 2. Server-code channels (the governance priority)
- **Coocon SASAPI** (M-STOCK, IBK, 신한, 현대해상) → COOCON_SASAPI_TRIAGE.md. `updateScript`→socket→
  `ScriptManager`→`ScriptEngine`/`V8ScriptEngine` `evaluateString`. Server **`isas.coocon.co.kr:443`**
  (svc `PUSANAPP`), devel `devel.mode`/`local.ip` override + fallback `183.111.160.145`, auth-txn over
  **plain HTTP** (`59.6.190.44:8900/cgi/sidea.authtr.cgi`), local proxy `127.0.0.1:1024/1025`. SEED-crypto,
  **no cert pin observed**. Scripts fetched by name+version, decrypted, eval'd — a bank-site scraper (mydata).
- **GPA GAD BeanShell** → GAD_API_RUNTIME_CAPTURE.md. `gad.api.gpakorea.com/campaign/{setup,prepare2,
  script/entry}` push BeanShell executed in-process. The whole channel (+ `type=5` CPS + `x-tdi-client-secret`)
  is **undocumented to integrators** (public api-doc = list/join/status/complete, types 0–4 only). iOS SDK
  (v0.1.9 XCFramework) is **asymmetric** — shares the API host + TDI linkage but ships no script interpreter
  (WKWebView `evaluateJavaScript` only). Version pinned rc.12 (matches runtime capture).

## 3. Other bundled surfaces (hygiene / defense-in-depth)
- **On-device AV** — AhnLab V3 (`com.ahnlab.enginesdk`) in the 4 Coocon apps + 빗썸; NSHC DroidX3 in PASS.
- **PKI zoo** — WIZVERA+SpongyCastle (신한/현대해상), SignKorea+Yettiesoft (Mirae/SK증권), DreamSecurity
  (우리/SK증권), RaonSecure (대부분), INITECH (IBK/현대캐피탈), NSHC nFilter keypad (우리/현대캐피탈).
- **adtech** — L.POINT (Buzzvil/Avatye/IGAWorks lockscreen), 우리WON카 (AdBrix/IGAWorks/adjust), 빗썸
  (Braze/AppsFlyer/IronSource), OK캐시백 (Fairytech/adjoe/Adison/IronSource). Offerwall deep-dives:
  TNK_FULLPASS.md (unpinned custom-ObjectInput deser = medium), TYRADS/ADISON triage (webview bridge = low–med).
- **drfn/chart** (M-STOCK) — "공유차트" posts chart image + **userId/userIp/deviceID + charted symbol + memo**
  over **plain HTTP to a hardcoded IP** (218.38.18.171). Not creds, but identifiers+watchlist in cleartext.
- **HMG platform** — Kia≈MyHyundai byte-identical (Mapbox/Datadog/Airbridge/Salesforce), no Coocon/Rhino.

## 4. Recommended actions
- **Institutions (banks/brokers using Coocon/GAD):** treat the server-script channel as a governed
  supply-chain code path — require **script signing + endpoint pinning**, audit scraped-data scope, and get
  the vendor to **disclose the channel** in integration docs. See VENDOR_HARDENING_REQUESTS.md.
- **Vendors:** GAD (disclose+constrain BeanShell, pin/sign), Coocon (sign scripts, pin `isas`, drop plain-HTTP
  auth-txn), TNK (class allow-list + pinning), Adison (domain allowlist + intent-scheme guard), drfn (HTTPS+PII).
- **Analysts:** for this xShield variant, carve directly (dexes plaintext); recover the native vault with
  `find_decryptor.py`; the server-code channels are the finding, not the RASP.

## Evidence & method
Reports in this dir: `XSHIELD_FLEET_SURVEY`, `COOCON_SASAPI_TRIAGE`, `GAD_*`, `TNK_*`, `TYRADS_*`,
`ADISON_*`, `VENDOR_HARDENING_REQUESTS`, `ISSUE5_GENERALIZATION`. Tooling: `.agents/skills/`
(`packer-detect`, `payload_triage`/`payload_decrypt`/`find_decryptor`, `sdk-carve`). Memory: [[xshield-fleet-coocon]],
[[gpa-gad-beanshell]], [[skp-xshield-assessment]].
