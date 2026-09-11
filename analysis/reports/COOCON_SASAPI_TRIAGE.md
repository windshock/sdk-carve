# Coocon SASAPI — server-driven JS scraping engine (in 4 KR financial apps)

**Status:** cpg-confirmed on M-STOCK; string-confirmed across the fleet (`payload_decrypt.py`);
**sandbox-escape PoC-confirmed → arbitrary in-process code** (see §Sandbox strength). **Severity: HIGH (design).**
**One line:** Four KR financial apps bundle **Coocon SASAPI** (`kr.co.coocon.sasapi`), a
screen-scraping/aggregation SDK that **downloads JavaScript from its server and executes it in-process via
Rhino/V8** with **no ClassShutter** — a server-driven code channel whose real ceiling is **arbitrary Java
execution** inside the financial app (PoC-confirmed), same/stronger class as GAD's BeanShell.

## Fleet presence (payload_decrypt base-apk dex scan)
| App | mgmt server | kr.co.coocon refs | Rhino refs |
|---|---|---|---|
| Mirae Asset M-STOCK | xo.dxshield.com | ~896–997 | ~817 |
| IBK i-ONE 기업 (com.ibk.scbs) | xo.dxshield.com | ~1281–1384 | ~707 |
| 신한 SOL저축은행 (com.shinhan.spbs) | xo.fxshield.co.kr | ~978–1081 | ~698 |
| 현대해상 Hi (m.hi.co.kr) | xo.fxshield.co.kr | ~971–1074 | ~767 |
| SK증권 주파수3 | (old framing) | ~10 (stub only) | — |

**SASAPI version diff (2026-09-11):** M-STOCK = `sdk version: 2.20.6`, IBK = `2.10.0`, 현대해상 = `2.10.0`,
신한 = version stored as a field (`MSDK_VERSION`/`sdkVersion`), no literal in strings. → **version is NOT
correlated with the dxshield.com vs fxshield.co.kr split** (M-STOCK & IBK both use dxshield yet differ
2.20.6 vs 2.10.0; IBK-dxshield and 현대해상-fxshield both 2.10.0). Coocon's own SDK versioning tracks each
app's integration date, orthogonal to NSHC's xShield mgmt server — two independent supply-chain layers.
The class structure (`sasapi/{SASManager, cert/Issac, crypt/AES256, sga/SASSGA, has160/*, scriptengine/*}`)
is identical across all four; only the point version differs.

The two `dxshield.com` apps (Mirae, IBK) are the most Coocon-embedded; both are brokerages. The full
`updateScript`→Rhino chain below was CPG-verified on M-STOCK; the other three carry the same package +
comparable ref counts (same engine). SK증권 has only a 10-ref stub (interface, not the full engine).

### Channel confirmed (not just the package) across all 4 apps
Carved `kr/co/coocon` straight from the **plaintext** base-apk dexes (no decrypt — this xShield variant
leaves app dexes in the clear). All four apps carry a **byte-identical Coocon class structure**:
- `Lkr/co/coocon/sasapi/scriptengine/ScriptEngine;` — the Rhino eval sink (holds `evaluateString`)
- `Lkr/co/coocon/sasapi/scriptengine/V8ScriptEngine;` — a **second JS engine (Google V8)**; Coocon can
  run server scripts on Rhino *or* V8.
- `Lkr/co/coocon/sasapi/script/ScriptManager;` + `ConnectionFailedException` + `ScriptNotFoundException`
  — the exceptions make the remote-fetch model explicit: scripts are **downloaded over the network**
  (ConnectionFailed) and may be **absent server-side** (ScriptNotFound).
- Per-app signature counts are near-identical (updateScript=1, loadScript=1, ScriptEngine=5,
  evaluateString=1–2, `java/net/Socket`=5–6, `org/mozilla/javascript`=6–9) — same SDK version, same channel.

So the server-driven JS channel is present and structurally identical in **M-STOCK, IBK, 신한, 현대해상**
(M-STOCK additionally CPG-flow-verified). Method names are unobfuscated (Rhino + Coocon public API).

## How it was found (full 2-skill chain)
1. `packer-detect` → M-STOCK (`com.miraeasset.trade`) = NSHC xShield/DxShield.
2. `xshield-reversal` → payload asset `assets/.b636…dex` statically decrypted (section0 config oracle +
   section1 PK oracle). Config: `com.miraeasset.trade, com.daewoo.mainlib.AppApplication, …, 1,
   **xo.dxshield.com**`. The plaintext class-map flagged `org/mozilla/javascript` (~700 refs, 4 dexes).
3. `sdk-carve` → carved `kr/co/coocon` (865 classes → 7877 methods) → jimple2cpg → joern source→sink.

## The server-script channel (structural chain, CPG-confirmed)
```
updateScript()  →  raw java.net.Socket (connect / setSoTimeout / get{In,Out}putStream)   ← download JS from server
      ↓
loadScript(String) / include(String)  →  ScriptEngine.a(String)  →  org.mozilla.javascript … evaluateString   ← eval in-process
```
- `ScriptEngine.a(String)` holds the **only** `evaluateString` call; its callers are `loadScript(String)`
  and `include(String)`; `updateScript()` opens a raw socket. So server-supplied JS reaches Rhino eval.
- **Auto-dataflow `network-read → evaluateString` = 0 flows** — this is a Joern stitching limitation across
  the socket→buffer→loadScript→eval hops, **NOT** evidence of no channel. The method-name + call-graph
  chain (`updateScript`(socket) → `loadScript` → `a` → `evaluateString`) is the conclusive evidence.
  (Recurring lesson: a degenerate 0-flow is not a negative.)

## Server endpoint + protocol (recovered 2026-09-11, from M-STOCK ScriptManager/SASManager/HttpManager)
- **Script server:** `isas.coocon.co.kr` (`SASManager.initInstance` default `"isas.coocon.co.kr:443:80"`
  = host:tlsPort:port), service ID **`PUSANAPP`**, type **`A`**. ISAS = Coocon's Internet Scraping/Aggregation
  service. TLS via `http/TLSOnlySocketFactory` (TLS-only; pinning not observed — standard-TLS trust).
- **Devel override (script-source redirection knob):** if system property `devel.mode=true`, the server is
  taken from system property `local.ip`, else falls back to **`183.111.160.145:443:80`**. `System.getProperty`
  (JVM props) — a build/host-settable switch that redirects where scripts are fetched from. Hygiene/risk flag.
- **Auth transaction:** `http://59.6.190.44:8900/cgi/sidea.authtr.cgi` — **plain HTTP** (plaintext auth channel).
- **On-device scraping proxy:** `127.0.0.1:1024/1025` (local proxy the engine drives the target webviews through).
- **Error log:** `https://isas.coocon.co.kr:8443/jsp/ins_errlog.jsp`.
- **Protocol (`ScriptManager.getScript`/`updateScript`):** scripts fetched by **`+`-joined names**, default
  **POST** (GET fetches only not-yet-cached names); each script cached in the `v` map as {contents, `getScriptVersion`
  = 10-digit version} so the client sends its version and the server returns newer JS. Retry via
  `updateScript _CONNECTION_TRY_COUNT`; responses SEED-decrypted then handed to `ScriptEngine`/`V8ScriptEngine`.
- **Net risk:** the eval'd JS originates at `isas.coocon.co.kr` over standard TLS (no pin observed) + a plaintext
  auth channel + a system-property server-redirect switch → transport integrity of the code channel rests on the
  device CA store. See VENDOR_HARDENING_REQUESTS.md §4 (script signing + endpoint pinning).

## Capability surface (carved CPG)
- JS-EVAL: `ScriptEngine` (Rhino) **and** `V8ScriptEngine` (Google V8) — two interchangeable engines.
  NET: raw `Socket` in `trx` (scraping transactions) + `updateScript` + `setProxy`; script fetch surfaced
  by `ConnectionFailedException`/`ScriptNotFoundException`. DEVICE-ID: 2. REFLECT/dyn: 6. CRYPTO: **KISA
  SEED-CBC** (Korean cipher) for its traffic.
- No `DexClassLoader`/`System.load` (JS is data-eval, not native code loading).

## Real app integration (M-STOCK, carved 2026-09-11)
How the host app actually wires the engine (app scraper `com.daewoo.mainlib.Scrap.aa.iIiIIIiiii()`):
```java
SASManager sm = SASManager.getInstance();
dc dcVar = new dc();                     // com.miraeasset.main.dc extends kr.co.coocon.sasapi.crypt.AbstractCrypto
sm.setObject(dcVar, <name>);             // the APP injects its OWN object into the script scope
sm.addSASRunCompletedListener(this); sm.addSASRunStatusChangedListener(this);
```
- `getInstance()` binds Coocon's own toolkit into the JS scope: **`system`=ScriptEngine** (whose JS-reachable
  methods include `getHttpRequest()`→HttpManager, `getSASSessions()`, `getDeviceID()`, `getUserInfo()`,
  **`addTrustedCertificateAuthority()`** = runtime CA trust, `loadScript`/`include`/`runScript`), plus
  `httpRequest`, `SASSessions`, `certManager`, `SASCipher`, `TouchEnKey`/`TouchEnKeyEx` (secure keypad), etc.
- The app *additionally* injects **`com.miraeasset.main.dc`** — a crypto bridge whose `dec()`/`enc()` route
  to the app's **`KeySecManager`/`SecManager` secure-key** decryption. So a server script gets Coocon's
  financial toolkit **plus the host app's secure-key crypto**.

## Sandbox strength — escape PoC-confirmed → arbitrary in-process code (2026-09-11)
`ScriptEngine.getInstance()` sets up Rhino with **`initSafeStandardObjects` + sealed scope only — it does
NOT call `setClassShutter`** (the `ClassShutter`/`visibleToScripts` strings in the dex are the bundled
Rhino library's own, not a Coocon-installed shutter — verified: no `setClassShutter` call in
`getInstance`/`initInstance`). With no ClassShutter, `initSafeStandardObjects` removes only the global
`java`/`Packages` — it does **not** stop the classic Rhino pivot `boundObject.getClass().forName('java.lang.
Runtime')…` off any exposed Java object.
- **Dynamically confirmed (local PoC, uncommitted):** ran the app's **bundled Rhino bytecode** (dex2jar) with
  the **real `ScriptEngine`** bound as `system` (v2) **and** the **real app object `dc`** injected via the
  engine's real `setObject()` (v3, matching §Real app integration). Controls: `java`/`Packages` globals
  blocked (safe objects working). Escape: `system.getClass()…exec('id')` **and** the app object
  `dc.getClass()…exec('id')` both returned real `id` output → **arbitrary in-process command execution**.
  So the escape works even off the *app's own* injected object — i.e., injecting any Java object into the
  scope opens it. Tooling note: this is pure-JVM Rhino semantics (Dalvik/ART identical); unidbg is native-only
  and N/A. PoC code kept local (method/result only in this report).

## Risk framing — HIGH (design; PoC-confirmed sandbox escape)
- **Ceiling is arbitrary in-process code**, not a bounded scraping API: the server (or a party who can swap
  the script) runs code inside a bank/broker app with the user's authenticated financial sessions, PKI,
  secure keypad, runtime CA trust, **and** the app's secure-key crypto — plus a confirmed escape to arbitrary
  Java. Same/stronger class as GPA GAD BeanShell (GAD had no ClassShutter either; here the app also hands in
  its own object).
- **Transport widens it:** no cert pinning observed on `isas.coocon.co.kr`, a plaintext-HTTP auth transaction,
  and a `devel.mode`/`local.ip` system-property switch that redirects the script source → a device-trusted-CA
  MITM can substitute the script and drive all of the above.
- **Not an allegation of malicious server content** (observed scripts were scraping logic). This is a
  **design-level exposure**: a bank/broker must govern it as a server-driven code path — script signing,
  endpoint pinning, an engine ClassShutter allow-list, and minimizing what host objects are injected.

## Second finding in the same dexes (hygiene/privacy — payload confirmed 2026-09-11)
`drfn/chart` (third-party charting SDK, `drfn.chart.base.{Save,Load}ChartController` + `COMUtil`) is a
**"공유차트" (shared-chart) community feature** that syncs over **plain HTTP to a hardcoded bare IP**:
`http://218.38.18.171/smartPhone/{upload,dnload,dnloadPro,delete}.php`.
- **`upload.php`** (multipart POST, `SaveChartController.HttpFileUpload`): the chart **image** (`userfile`,
  `ipodfile.jpg`) **plus form fields** `saveDate, userId, userIp, verInfo, title, detail, chartMode,
  divideInfo, apCode, graphList, **deviceID**, analInfo, codeName, **symbol, lcode**, dataTypeName, count,
  viewCount, valueOfMin`.
- **`delete.php?uid=…&deviceID=…`** sends the **device identifier** in the query string (cleartext).
- Downloaded records carry `deviceID, userId, userIp` alongside the chart config.
- **So the payload is NOT "chart data only"**: it ships **three identifiers (userId / userIp / deviceID)**,
  the **charted security (`symbol`/`codeName`/`lcode`)** (reveals watchlist/interest), and user-entered
  `title`/`detail` (memo) — all **cleartext HTTP to a hardcoded third-party IP** inside a brokerage app.
- **Not credentials/orders**, and chart-share is opt-in-by-design, but: plaintext transport + device/user
  identifiers + a bundled chart vendor's own bare-IP server = a real privacy/hygiene flag. Recommend HTTPS,
  drop/deviceID-minimize the shared-chart upload (or explicit consent), and review the third-party server.

## Follow-ups
- Recover Coocon's `updateScript` server endpoint/protocol (behind SEED + likely the payload/config).
- ~~Compare Coocon across the other Rhino-bearing apps~~ **DONE** — confirmed in IBK, 신한, 현대해상 (table above).
  Next: diff the Coocon *version* across them (is dxshield.com vs fxshield.co.kr correlated with a build?).
- Confirm what data the scraping scripts collect + exfiltrate (needs the server-supplied JS or a dynamic run).
