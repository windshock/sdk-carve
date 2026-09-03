# Pre-carve: container normalization & payload discovery

sdk-carve assumes it can get at an app's bytecode. Some packers break that assumption at the
**APK-container** layer: they tamper the ZIP so Android still installs the app but `aapt`,
`apktool`, `jadx`, and `dex2jar` choke, and they hide the real SDK as an encrypted asset
loaded at runtime. This adds the missing **stage 0** before bytecode discovery:

```text
APK
 └─ [pre-carve] container normalize  (scripts/apk-normalize.py)   ← fixes ZIP tamper, flags payloads
 └─ [pre-carve] payload discover/decrypt (family-specific)        ← recovers hidden DEX
      ↓
 normalized APK / real classes.dex
      ↓
 dex2jar → detect.py → carve.sh → CPG/CodeQL   (the normal method)
```

Worked example: **Konfety / CaramelAds** (5 samples, Hybrid Analysis; sha256-verified).

## 1. Container tamper (binary-confirmed on all 5)

Parsed from the raw ZIP structures (not a library that would reject them):

| Tamper | Evidence | Effect |
|---|---|---|
| **Fake "encrypted" flag** | General-Purpose **bit 0 set on every entry** (`gp=0x0001`), nothing actually encrypted | `unzip`/`7z` refuse the entries (why the asset looked unextractable) |
| **Bogus compression method** | `AndroidManifest.xml` declares method **`0x0C` (BZIP2)** but the data is raw AXML (`03 00 08 00`, size 26312) — i.e. STORED | `aapt`/`apktool` report "AndroidManifest.xml is corrupt" |
| **Size lies** | manifest `csize=13495` while the true on-disk span is `26312` | standard parsers read a truncated/incoherent entry |
| **Decoy `classes.dex`** | 7–8 KB, 7–14 empty stub classes (`class K { void GCw(){} }`) | nothing real for a bytecode tool to find |

This is the SoumniBot/Konfety technique: valid enough for Android's lenient loader, invalid
for strict static tools. `scripts/apk-normalize.py` is a **generic** fix — it clears the fake
encryption flag, re-derives each entry's real bytes (deflate or stored) from neighbouring
local-header offsets, and rebuilds a clean STORE ZIP; it also reports the anomalies and
flags high-entropy `assets/*` (candidate packed payloads).

```
$ apk-normalize.py evil.apk normalized.apk
normalized 166 entries -> normalized.apk
ANOMALIES:
  fake-enc-flag              x166 (all entries — classic fake-encryption tamper)
  bogus-method-0x0c          AndroidManifest.xml
  csize-lie                  AndroidManifest.xml
  decoy-classes.dex          7732B
  packed-asset?              assets/2127139622672352244 2209433B ent=8.00
$ aapt dump badging normalized.apk        # was "corrupt" before
package: name='com.herocraft.game.freemium.catchthecandy' versionName='63.8' …
```

Normalization alone recovers the **evil-twin decoy identity** (`com.herocraft…catchthecandy`,
"Catch the Candy") and its AppLovin-mediation manifest — and points at the packed asset.

## 2. Payload discovery / decrypt

The flagged asset (entropy 8.00) is: DEFLATE-compressed (behind the fake enc flag) →
XOR-encrypted with a **`java.util.Random` keystream** → an inner ZIP holding the real
`classes.dex`. The loader (`svmmk/…/GCw`, `IEk`) does this via reflection + a string
deobfuscator that uses the same `Random`-XOR trick.

- Keystream = `java.util.Random(seed).nextBytes()`, and across the corpus
  **`seed = numeric_asset_name + 0xFFFF`** (verified 5/5) — no per-sample RE needed.
- `scripts/konfety-unpack.py <apk> <out>` inflates the asset, XOR-decrypts, and extracts the
  inner ZIP. Result on all 5: an identical **6,104 KB / 6,777-class** second-stage DEX.

## 3. What the hidden payload actually is

Carving the recovered DEX (the SDK that was invisible before):

- Ad stack: **InMobi** (`in.inmobi`) + `com.adcommercial`, `com.gnet`, `com.nextg`, `sdk.*`.
- **No** in-code emulator/debugger/root checks and **no** Goldoson-style packet-capture
  blocklist — Konfety's evasion budget is spent on the packer, not runtime guards.
- **Install-source gating** (`getInstallerPackageName` — SlopAds-style selective activation).
- Hidden C2 (only visible post-unpack): `http://api.jetengine.be/`, `http://one.upyourphone.me/`.

All 5 evil-twins carry the **same** payload (only the decoy wrapper + asset-name/seed differ)
→ a single shared second-stage across the cluster.

## Takeaway

The finding isn't "Konfety broke sdk-carve" — it's that sdk-carve was missing a
**container-normalization / payload-discovery** stage before bytecode discovery. The
generic `apk-normalize.py` handles the ZIP-tamper class (Konfety *and* SoumniBot and future
malformed-APK packers); the family-specific decrypt (`konfety-unpack.py`) is the plug-in for
the payload stage. Runtime fallback when a payload can't be decrypted statically:
`frida-dexdump` / BlackDex to dump the DEX from memory.
