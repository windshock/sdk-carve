# Coocon SASAPI — server-driven JS scraping engine (in 4 KR financial apps)

**Status:** cpg-confirmed on M-STOCK (via sdk-carve on the decrypted payload); string-confirmed across
the fleet (`payload_decrypt.py` base-apk dex scan).
**One line:** Four KR financial apps bundle **Coocon SASAPI** (`kr.co.coocon.sasapi`), a
screen-scraping/aggregation SDK that **downloads JavaScript from its server over a raw socket and
executes it in-process via Rhino (`org.mozilla.javascript`)** — a server-driven code-execution channel,
same threat class as GAD's BeanShell channel (RCE-by-design), here for financial-site scraping (mydata-style).

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

## Risk framing
- **By design**: Coocon is a legitimate KR scraping/aggregation SDK (banks/cards/mydata). Its power is
  intrinsic — the server can push arbitrary JS that runs in the host (financial) app's process. Trust
  reduces to Coocon's server + transport integrity (SEED-encrypted, but confirm cert/endpoint pinning).
- **Same threat class as GPA GAD BeanShell** (server → in-process code eval). Not malware; a supply-chain
  surface a bank/broker should govern (vendor server integrity, script signing, scope of scraped data).

## Second finding in the same dexes (hygiene, not malicious)
`drfn/chart` (charting SDK) `LoadChartController`/`SaveChartController`/`COMUtil` sync user chart configs
over **plain HTTP to a bare IP**: `http://218.38.18.171/smartPhone/{upload,dnload,dnloadPro,delete}.php`.
Unencrypted + hardcoded IP in a securities app = a hygiene/privacy flag (recommend HTTPS + review payload).

## Follow-ups
- Recover Coocon's `updateScript` server endpoint/protocol (behind SEED + likely the payload/config).
- ~~Compare Coocon across the other Rhino-bearing apps~~ **DONE** — confirmed in IBK, 신한, 현대해상 (table above).
  Next: diff the Coocon *version* across them (is dxshield.com vs fxshield.co.kr correlated with a build?).
- Confirm what data the scraping scripts collect + exfiltrate (needs the server-supplied JS or a dynamic run).
