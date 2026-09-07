# Packer / shielder identification (pre-carve stage 0)

## Why this belongs in sdk-carve

sdk-carve's whole value proposition is *soundness*: carve the target SDK faithfully so that a
"clean" verdict means clean, not "the tool couldn't see it." The project already documents its
own failure boundary — obfuscation, packing, and runtime code-loading (see
[`docs/FIDELITY.md`](FIDELITY.md), [`docs/PRE_CARVE.md`](PRE_CARVE.md)). A **packer or app-shielder
sits squarely on that boundary and defeats a static carve silently**:

- **String encryption** → the IOC/endpoint sweep (`ioc-sweep.sh`, `class-map.py`) reads encrypted
  blobs and returns *nothing* → a false-negative that looks like a clean result.
- **Encrypted payload DEX** → the app's real code is decrypted into memory at runtime; the shipped
  `classes.dex` is a stub/loader. A bytecode carve finds ~none of the SDK and reports it absent →
  the exact "silent under-scope" failure sdk-carve exists to prevent (cf. the
  [sdk-carve completeness finding](../analysis) where a whole-app CPG silently dropped the target
  SDK in 7/11 apps).

The subtlety: `apk-normalize.py` only catches a **tampered container** (fake ZIP flags, decoy dex —
Konfety/SoumniBot style). A *commercial* shielder (NSHC xShield/DxShield, AppSealing, DexGuard,
Bangcle, Tencent Legu, 360 Jiagu…) repackages into a **perfectly valid ZIP** — aapt/apktool/jadx
are all happy — yet the strings are encrypted and the payload is runtime-loaded. Normalization sees
nothing wrong. **You must identify the shielder first and let its known behaviour tell you whether a
static carve is VALID, DEGRADED, or BLIND.** That is stage 0.

```text
Stage 0a  PACKER / SHIELDER ID          scripts/packer-detect.py   ← THIS (identify + carve-impact)
Stage 0b  container normalization       scripts/apk-normalize.py   (fix ZIP tamper, flag payloads)
Stage 1   loader / decoy detection      (tiny classes.dex + reflection stubs)
Stage 2   encrypted-payload discovery   (high-entropy assets/*)
Stage 3a  static decrypt               scripts/konfety-unpack.py / mobidash-unpack.py
Stage 3b  runtime / pre-sealed DEX dump frida-dexdump · pre-sealed build   (when no key is recoverable)
Stage 4   SDK carving                  dex2jar → detect.py → carve.sh → CPG/CodeQL
```

## The connection to awakewiki.org/packers

[AWAKE wiki's packer catalog](https://awakewiki.org/packers/) is a **knowledge base**: for each
Android packer/shielder it records the vendor, the detection markers (native `.so` names, asset
paths, package names, file markers), whether it's commercial or a malware packer, an unpacking
difficulty, and the unpacking method (static decrypt vs runtime memory dump). That is precisely the
lookup table stage 0 needs. Two ways it plugs into the project:

1. **Signature source.** `packer-detect.py`'s built-in table is seeded from the AWAKE catalog
   (360 Jiagu `libjiagu*.so`/`jiagu_data.bin`; Bangcle/SecNeo `libsecexe/libsecmain/libSecShell` +
   `secData0.jar`; Tencent Legu `libshell*` + `assets/0OO00l111l1l`; DexProtector `libalice.so`;
   AppSealing `libcovault-appsec.so`; LIAPP `com.lockincomp`; zShield `.szip`; Ducex `libducex.so`;
   iJiami; Appdome; Promon; Virbox; Verimatrix; and the malware packers Hqwar, GoldCrypt, and
   **Necro** — a family sdk-carve already tracks). APKiD, if installed, is run and merged as the
   authoritative engine; the built-in table is the offline fallback.

2. **Difficulty/method → routing.** The wiki's "difficulty" and "method" columns map directly onto
   the pre-carve routing: *memory-dump* packers (Jiagu/Bangcle/Legu/iJiami) → Stage 3b dynamic dump;
   *static-decrypt* packers (Konfety/MobiDash/Ducex) → Stage 3a; *server-token* shielders
   (LIAPP/AppSealing) → note the limitation. `packer-detect.py` turns that into a machine verdict +
   exit code so the pipeline can branch automatically.

### Where the project extends the wiki

The AWAKE catalog is thin on **Korean financial RASP shielders**. Our first-party reverse of the SKP
apps filled that gap — and is contributed back into the signature table:

- **NSHC xShield / DxShield** (`libdxbase.so` + `libnms.so`/`libeca758.so`, `com.xshield`) — not in
  the wiki as of this writing; identified via APKiD (`libdxbase.so → DxShield`) and confirmed by a
  full static reverse (string vault cracked, encrypted payload DEX proven runtime-decrypt-only).
- **LIAPP**, **nProtect/AppGuard** — Korean shielders the wiki lists only partially.

So the relationship is bidirectional: the wiki seeds our detector, and our reverse-engineering
findings (xShield carve-impact, Necro loader fingerprint) extend the wiki's coverage.

### "Recognise known AND malicious packers"

- **Known** packers/shielders → matched by signature (the table above). These are usually *benign*
  on a legit app (a bank app being xShield-shielded is expected) but they still **degrade the
  carve**, which is what stage 0 flags.
- **Malicious / unknown** packers → two paths. (a) Named malware packers (Hqwar, GoldCrypt, Necro)
  are in the signature table. (b) A *custom/unidentified* packer is caught by a conservative
  structural heuristic: a **stub-sized `classes.dex` paired with an encrypted-looking asset that
  dwarfs it** (payload > loader, entropy ≥ 7.9). This deliberately does **not** fire on ordinary
  high-entropy assets (compressed `.woff` fonts, Cocos2d `.png/.jsc/.mp3`, ML models) — validated
  against TMAP and a Cocos2d SpinOk sample, which both come back VALID. It *does* fire on the Konfety
  7 KB decoy stub. An unknown packer on an app that has no business being packed is itself a triage
  signal (exit 30 = "treat as hostile, identify before carving").

## Carve-impact model (the output that matters)

| impact flag | meaning | effect on carve | exit |
|---|---|---|---|
| *(none)* | no packer, or obfuscation-only (R8/ProGuard/Redex) | **VALID** — proceed to carve | 0 |
| `strings` | app strings encrypted (DexGuard, most shielders) | **DEGRADED** — structure carveable, IOC/endpoint sweep unreliable | 10 |
| `dex` | real code in a runtime-decrypted payload DEX | **BLIND** — bytecode carve of `classes.dex` under-scopes | 20 |
| *(unknown indicators)* | stub dex over an encrypted payload, no known sig | **SUSPECT** — custom/malware packer | 30 |
| `rasp` | anti-debug/root/emu/frida | only affects a *dynamic* dump (needs bypass); static unaffected | — |

Obfuscators (R8/ProGuard/Redex) are catalogued but do **not** degrade the carve — `detect.py`'s
renamed-root resolver already handles renaming; that is a solved problem, not a packing problem.

## Usage

```bash
scripts/packer-detect.py app.apk           # human report + exit code
scripts/packer-detect.py --json app.apk    # machine-readable (detections + carve-impact + apkid)

# typical gate in a pipeline:
scripts/packer-detect.py app.apk; case $? in
  0)  ;;                                    # carve directly
  10) echo "carve structure; defer IOC verdicts to dynamic";;
  20) echo "recover payload DEX first (pre-sealed / dynamic dump), then carve THAT";;
  30) scripts/apk-normalize.py app.apk out.apk; apkid app.apk;;   # identify/unpack first
esac
```

## Worked example — OK Cashbag / NSHC xShield (exit 20, BLIND)

```
$ scripts/packer-detect.py ok-cashbag-7-1-9.apk
VERDICT: static carve BLIND — real code is in a runtime-decrypted payload DEX; bytecode carve
         on classes.dex will silently under-scope
  [SHIELDER ] NSHC xShield / DxShield  (NSHC)
             carve-impact: strings,dex,rasp
             evidence: lib:libdxbase.so, lib:libnms.so, lib:libeca758.so, pkg:com/xshield/
```

Why this is the poster child for stage 0: OK Cashbag is a clean, valid APK — `apk-normalize.py`
finds nothing to fix. Yet a naive `dex2jar → detect.py → carve.sh` on it would carve the `com.xshield`
loader and a pile of encrypted-string blobs and conclude the bundled ad/reward SDKs (Fairytech Moment,
gad, Tyrads) are "absent or benign." They aren't visible statically at all — the real SDK code and its
endpoints live in the encrypted payload DEX (`assets/.4ee57bec…dex`, decrypted only at runtime; proven
by the string-cipher reverse and the 6-evidence terminal boundary). Correct handling: recover the
payload from a **pre-sealed build** or a **sanctioned dynamic dump**, then carve *that*. Stage 0 makes
that decision explicit instead of shipping a false negative.

## Extending the catalog

Add a dict to `SIGS` in `packer-detect.py`:

```python
dict(name="<packer>", vendor="<vendor>", category="shielder|packer|malware|obfuscator",
     libs=[r"lib<x>\.so"], assets=[r"assets/<x>"], pkgs=[r"<pkg>/"], markers=[r"<zip path>"],
     impact=dict(strings=<bool>, dex=<bool>, rasp=<bool>), note="unpacking route")
```

Prefer high-specificity markers (a unique `.so` basename or asset path) over package substrings, and
set `impact` from the packer's *documented* behaviour (AWAKE method column) or a first-party reverse.
`rasp` alone (no `strings`/`dex`) keeps the static carve VALID — it only matters for a dynamic dump.
