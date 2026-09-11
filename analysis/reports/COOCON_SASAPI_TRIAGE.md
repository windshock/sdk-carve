# Coocon SASAPI — server-driven JS scraping engine (found in Mirae Asset M-STOCK)

**Status:** cpg-confirmed (static, via sdk-carve on the decrypted xShield payload).
**One line:** M-STOCK bundles **Coocon SASAPI** (`kr.co.coocon.sasapi`), a screen-scraping/aggregation SDK
that **downloads JavaScript from its server over a raw socket and executes it in-process via Rhino
(`org.mozilla.javascript`)** — a server-driven code-execution channel, same threat class as GAD's
BeanShell channel (RCE-by-design), here for financial-site scraping (mydata-style).

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

## Capability surface (carved CPG)
- JS-EVAL (Rhino): 1 (ScriptEngine.a). NET: raw `Socket` in `trx` (scraping transactions) + `updateScript`
  + `setProxy`. DEVICE-ID: 2. REFLECT/dyn: 6. CRYPTO: **KISA SEED-CBC** (Korean cipher) for its traffic.
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
- Compare Coocon presence/version across the other Rhino-bearing apps (Shinhan, Hyundai Marine).
- Confirm what data the scraping scripts collect + exfiltrate (needs the server-supplied JS or a dynamic run).
