# Goldoson anti-analysis guard — packet-capture app detection (11/11, binary-confirmed)

Phase A deliverable (see [`../PLAN.md`](../PLAN.md)). Grounds the reference docs'
"highest-value research angle" in cross-sample binary evidence: Goldoson/SMARTLB suppresses
its own collection/ads when a **network/packet-capture inspection app** is installed — a
2023-era anti-analysis technique **not documented in the original McAfee report**.

## Mechanism  (`binary-confirmed`)

`c/c.l(Context)` (TMAP; equivalent obfuscated method in every sample) hardcodes a JSON
list of AES-encrypted package names, decrypts each, and returns `true` if any is installed;
callers short-circuit collection/ads on `true`.

```java
// com/smart/sklb/edge/c/c.java  (JADX)
public static boolean l(Context context) {
    bg.c cVar = new Gson().fromJson(
      "{\"packages\":[{\"name\":\"o9G9dG9ID8E+koIqtKT1y1V83uSCWzE8Hu7lN1r\\/ho4=\"},"
      + "{\"name\":\"cnCexRUcqgrWpl43fnRUZQ==\"}, ... ]}", bg.c.class);
    for (int i = 0; i < cVar.a().size(); i++)
        if (f(context, e.a(cVar.a().get(i).a())))   // e.a = AES decrypt ; f = isInstalled
            return true;
    return false;
}
```

```java
// com/smart/sklb/edge/c/e.java  — AES-256/CBC/PKCS5, zero IV, base64 input
SecretKeySpec k = new SecretKeySpec("aoKoVu#aiSkjwicO!@)(%^Zdh18zr!Oz".getBytes("UTF-8"), "AES");
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(DECRYPT, k, new IvParameterSpec(new byte[16]));   // IV = 16 × 0x00
```

**Crypto parameters (identical in every key-bearing sample):**
- key (ASCII): `aoKoVu#aiSkjwicO!@)(%^Zdh18zr!Oz` (AES-256)
- key (hex): `616f4b6f5675236169536b6a7769634f21402928255e5a646831387a72214f7a`
- IV: 16 × `00`; mode `AES/CBC/PKCS5Padding`; input base64-decoded

**Decrypted blocklist (5 network/packet-capture / traffic-analysis apps):**

| Package | App |
|---|---|
| `app.greyshirts.sslcapture` | SSL Capture |
| `com.ddm.iptools` | IP Tools |
| `com.myprog.netscan` | Network Scanner |
| `com.myprog.netutils` | Net Utils |
| `jp.co.taosoftware.android.packetcapture` | tPacketCapture |

## Cross-app result  (`binary-confirmed`, 11/11)

All 11 samples carry the **identical** guard: same AES key, same ciphertext, same 5 apps.
The blocklist is never stored in plaintext.

| Location of guard | Apps |
|---|---|
| inside the carved Goldoson SDK (9) | TMAP, SwipeBrickBreaker, compass, gomplayerko, megabox, somnote, worldcup, lottecinema, psynet |
| in the shaded-lib package excluded by the carve's size/depth guard (2) | audiorecorder (`e/…`), mafu (`d/e/a/a/…`) — same key+list, confirmed from the full app jar |

That the blocklist is byte-identical across independently-obfuscated apps is strong
evidence of a **single shared SDK source/build**, not per-app reimplementation.

## Candidate domains, reclassified  (`binary-confirmed` roles)

The 5 non-McAfee domains surfaced by the carve are Retrofit `baseUrl`s — but mostly of
**co-bundled sibling ad modules**, not Goldoson's collection C2. Call-path/class evidence:

| Domain | baseUrl class | Belongs to | Role |
|---|---|---|---|
| `appservice9.com` | `notii/network/WeatherRestClient` (+ `/policy/com.sdk.notii`) | **notii** weather/notification-push SDK | ad-content/config + developer/policy site |
| `retoore.com` | `notii/network/RetrofitClient` | notii | module API |
| `huejura.com` | `notii/network/m` | notii | module API |
| `trs.bestsmartshop.net` | `…/S_MALL_RestClient` (+ `/goods/detail?code=`) | **S_MALL** shopping module | ad-content (WebView deep-links) |
| `barivemi.net` | `…/nzcvt/RestClient` (Goldoson nepkt-equivalent) | **Goldoson SMARTLB** | ad/edge endpoint (kialant.com-equivalent) |

**Conclusion:** only `barivemi.net` is Goldoson-core infrastructure; the other four are
backends of sibling bundled ad SDKs (notii push, S_MALL shopping) that ship under the same
obfuscated root. This refines the earlier "5 new Goldoson C2" to "1 Goldoson edge endpoint
+ 4 sibling-module backends" — promote to IOC only with that scope.

## Hunt rule (research; validate before production)

```yara
rule Android_Goldoson_AntiAnalysis_Guard
{
    meta:
        description = "Goldoson/SMARTLB installed packet-capture app guard; 11/11 samples"
        note        = "AES-256/CBC key + byte-identical encrypted blocklist across samples"
    strings:
        $key       = "aoKoVu#aiSkjwicO!@)(%^Zdh18zr!Oz" ascii
        // AES/CBC-encrypted, base64; identical ciphertext across samples (pre-'/' fragments):
        $c_iptools = "cnCexRUcqgrWpl43fnRUZQ==" ascii                  // com.ddm.iptools
        $c_sslcap  = "o9G9dG9ID8E+koIqtKT1y1V83uSCWzE8Hu7lN1r" ascii   // app.greyshirts.sslcapture
        $c_pcap    = "H6PS4NeH0dcyn+cpMir8+e+zII" ascii                // jp.co.taosoftware…packetcapture
        $json      = "\"packages\":[{\"name\":\"" ascii
    condition:
        $key or (2 of ($c_*)) or ($json and 1 of ($c_*))
}
```

The encrypted-string set is far more lineage-specific than generic APIs (`WebView`,
`PackageManager`); it is the seed for the corpus reverse-search (PLAN Phase B / research
"Final priority #3").

## Significance & next step

- **Timeline:** places a working installed-analysis-tool blocklist in **2023**, ahead of /
  parallel to the better-documented anti-analysis of SpinOk (sensor sandbox), Necro
  (`isAdb/isProxy/isSimulator/isDebug`), SlopAds (debug/emulator/root), MobiDash
  (`Proxy.NO_PROXY`). See the anti-analysis-evolution table in the lineage doc.
- **Next (Phase B, authorization-gated):** reverse-search the exact 5 package strings + the
  ciphertext/key across AndroZoo/Koodous to test whether this guard is a reusable code
  lineage — the project's key research question.

## Reproduce

```bash
# decrypt one entry
echo -n 'cnCexRUcqgrWpl43fnRUZQ==' | base64 -d | \
  openssl enc -d -aes-256-cbc \
    -K 616f4b6f5675236169536b6a7769634f21402928255e5a646831387a72214f7a \
    -iv 00000000000000000000000000000000            # -> com.ddm.iptools

# whole blocklist from any carved SDK jar (or full app jar)
python3 goldoson-samples/analysis/decrypt_blocklist.py <scoped-or-app>.jar
```
