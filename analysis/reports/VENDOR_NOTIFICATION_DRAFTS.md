# Vendor notification drafts (coordinated disclosure) — NOT YET SENT

Ready-to-send coordinated-disclosure notices distilled from the triage + VENDOR_HARDENING_REQUESTS.md.
**Status: DRAFT.** Actually contacting a vendor is an outbound action that requires explicit sign-off
(recipient, channel, timeline, what's shared). Nothing here has been sent. Findings are static/CPG
design-weakness observations — **no active exploitation or malware is alleged**. Coordinate timing with
the affected host institutions (banks/brokers) where a vendor SDK ships inside their app.

Suggested framing for all: 90-day coordinated disclosure, offer to share the specific report + method,
no samples/PoC in the first contact, ask for a security contact + acknowledgement.

---

## A. NSHC — xShield / DxShield (RASP)
**Contact:** NSHC security/support (KR). **Class:** informational (no vuln alleged).
> We analyzed a set of Korean Android apps shielded with xShield/DxShield. Two neutral observations for
> your awareness: (1) in the builds we saw, the app's real `classes*.dex` remain plaintext in the base
> APK — the protection is runtime RASP + a native string vault, not DEX confidentiality; customers who
> expect code confidentiality should be aware. (2) The native string vault (decryptor auto-located per
> build, MBA seed `0x86817231`) is statically recoverable, so anti-analysis IOC lists inside it are not
> secret. No vulnerability is claimed; sharing so your customer guidance can be accurate.

## B. Coocon — SASAPI scraping SDK  (+ host banks/brokers: Mirae Asset, IBK, Shinhan, Hyundai Marine)
**Contact:** Coocon security + each host institution's security team. **Class:** supply-chain design.
> Coocon SASAPI (`kr.co.coocon.sasapi`) downloads JavaScript from `isas.coocon.co.kr` and executes it
> in-process via Rhino/V8 (`updateScript`→`ScriptManager`→`ScriptEngine.evaluateString`). This is a
> server-driven in-process code channel: the server (or a party with a device-trusted cert) can run
> arbitrary script inside the host financial app. We observed: no certificate pinning on the script
> endpoint, a plaintext-HTTP auth transaction (`59.6.190.44:8900/cgi/sidea.authtr.cgi`), and a
> `devel.mode`/`local.ip` system-property switch that redirects the script source. Requests: sign the
> served scripts (host-verifiable), pin the endpoint, remove the plaintext auth channel and the devel
> override from release builds, and document the scraped-data scope for integrating institutions.

## C. drfn — charting SDK (host: Mirae Asset M-STOCK)
**Contact:** drfn (chart vendor) + Mirae Asset security. **Class:** privacy/hygiene.
> The "공유차트" (shared-chart) feature POSTs to `http://218.38.18.171/smartPhone/upload.php` over
> **plaintext HTTP** a chart image plus `userId`, `userIp`, `deviceID`, the charted security
> (`symbol`/`codeName`/`lcode`), and a user memo (`title`/`detail`); `delete.php` sends `deviceID` in the
> query. Inside a brokerage app this exposes device/user identifiers and a user's watchlist in cleartext
> to a hardcoded third-party IP. Requests: move to HTTPS, drop/minimize `deviceID` and other identifiers
> (or gate behind explicit consent), and review the third-party server placement.

## D. GPA KOREA — GAD SDK (Syrup adtech)  (+ Syrup-bundled host apps)
**Contact:** GPA KOREA security. **Class:** supply-chain design.
> The GAD SDK executes server-supplied BeanShell in-process (`campaign/{setup,prepare2,script/entry}`),
> a channel absent from the public integration docs (which describe only list/join/status/complete,
> types 0–4). Observed script content was benign, but the channel is code-execution-by-design: server or
> transport integrity equals code execution in the host app. Requests: disclose the channel to
> integrators, constrain the interpreter (pin BeanShell ≥2.0b6 or move to an allowlisted command set),
> sign served scripts + pin the delivery endpoint, and stop injecting live app objects into script scope.
> (The iOS SDK does not ship an equivalent interpreter — this is an Android-specific exposure.)

## E. TNK Factory / Adison  (offerwall SDKs)
**Contact:** each vendor's security. **Class:** design/hygiene.
> - **TNK:** the `api3.tnkfactory.com` transport is not certificate-pinned and a custom `ObjectInput`
>   deserializes responses without a class-name allow-list (Externalizable-gated, app classloader,
>   JEP-290-bypassing). A party with a device-trusted cert could reach the gadget. Requests: class
>   allow-list, a type-safe wire format, cert pinning; remove the shipped trust-all `NullHostNameVerifier`.
> - **Adison:** the web→app bridge exposes `openExternal("intent://…")`→`Intent.parseUri` (intent-scheme
>   redirection), a web-specified `packageName`, and no destination-domain allow-list for in-app opens.
>   Requests: destination-domain allow-list, constrain the intent-scheme handling, validate `packageName`.

---
Evidence + method per item: the linked triage reports + `.agents/skills/` tooling. Sample binaries stay
local (never attached to a first contact).
