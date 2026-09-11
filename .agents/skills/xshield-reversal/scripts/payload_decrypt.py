#!/usr/bin/env python3
"""xshield-reversal Phase 1 — static payload section decrypt (oracle, no seeds/addr needed).

The payload asset's encrypted sections use an MSVC-LCG XOR stream (s=s*0x343FD+0x269EC3, key=s>>16).
Instead of deriving the per-section seed, brute-force it with a known-plaintext oracle:
  section0 (boot config, text)  -> the app PACKAGE name (first field) is known plaintext
  section1 (component jar)       -> "PK\x03\x04" zip magic is known plaintext
This recovers the config (Application/launcher/MODE/**FxShield/DxShield server**) and the hidden
component classes.dex + its SDK inventory. Arch-independent (works on any apk/xapk). Validated on
OK Cashbag / PASS by SKT / M-STOCK (byte/md5-matched).

usage: payload_decrypt.py <apk|xapk|dir> [package-prefix]
       (package auto-derived from the apk if not given)
requires: a C compiler (cc) for the 2^32 seed brute (seconds).
"""
import sys, os, re, zipfile, glob, tempfile, subprocess, struct, io, collections

def find_base(path):
    """Return (base_apk_bytes_path, asset_name, asset_bytes) — the apk carrying assets/.<hex>.dex."""
    cands = []
    if os.path.isdir(path):
        cands = glob.glob(os.path.join(path, '**', '*.apk'), recursive=True)
    elif path.endswith('.apk'):
        cands = [path]
    else:  # xapk/zip/apks bundle
        z = zipfile.ZipFile(path); td = tempfile.mkdtemp(prefix='xshdec-')
        for n in z.namelist():
            if n.endswith('.apk'): z.extract(n, td)
        cands = glob.glob(os.path.join(td, '**', '*.apk'), recursive=True)
    for a in cands:
        try: za = zipfile.ZipFile(a)
        except Exception: continue
        for n in za.namelist():
            if re.match(r'assets/\.?[0-9a-f]{16,}\.dex$', n):
                return a, n, za.read(n)
    return None, None, None

def derive_pkg(apk):
    try:
        out = subprocess.run(['aapt', 'dump', 'badging', apk], capture_output=True, text=True, timeout=60)
        m = re.search(r"package: name='([^']+)'", out.stdout)
        if m: return m.group(1)
    except Exception: pass
    # fallback: package string near the top of the (binary) AndroidManifest
    try:
        mani = zipfile.ZipFile(apk).read('AndroidManifest.xml')
        for m in re.finditer(rb'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})', mani):
            s = m.group(1).decode()
            if s.count('.') >= 2 and not s.startswith('android.'): return s
    except Exception: pass
    return None

C = r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
static uint8_t d[8000000]; static long n; static uint8_t o[8000000];
#define SEEDMAX 0x1000000ULL   /* all observed xShield section seeds are < 2^24 */
static int eocd(long L){for(long i=L-4;i>=0;i--)if(o[i]==0x50&&o[i+1]==0x4b&&o[i+2]==0x05&&o[i+3]==0x06)return 1;return 0;}
int main(int ac,char**av){
  FILE*f=fopen(av[1],"rb"); n=fread(d,1,sizeof d,f); fclose(f);
  const char*pk=av[2]; int pl=strlen(pk); if(pl>9)pl=9;
  // section0 data @0x224 = [keyblock][config text]; text-start varies by engine/stub-size -> scan it.
  long TXT=-1, S0=-1;
  for(long t=0x234, k=0; k<33 && S0<0; k++, t = 0x234 + ((k&1)?(k+1)/2:-(k/2))){  /* 0x234 first, then spiral out */
    if(t<0x224) continue;
    uint8_t req[9]; for(int i=0;i<pl;i++)req[i]=d[t+i]^(uint8_t)pk[i];
    for(uint64_t s=0;s<SEEDMAX;s++){uint32_t y=s;int ok=1;for(int i=0;i<pl;i++){y=y*214013u+2531011u;if(((y>>16)&0xff)!=req[i]){ok=0;break;}}if(ok){S0=s;TXT=t;break;}}
  }
  if(S0<0){printf("SECTION0_SEED_NOTFOUND\n");return 1;}
  uint32_t y=S0; char cfg[2048]; int tl=0;
  for(long i=0;i<2000;i++){y=y*214013u+2531011u;int c=d[TXT+i]^((y>>16)&0xff); if(c<0x20||c>0x7e)break; cfg[tl++]=c;}
  cfg[tl]=0; printf("CONFIG\t%s\n",cfg);
  long s1=TXT+tl+4;                                // section1 data offset estimate (text end + len field)
  // section1: scan a window for a PK-decodable, EOCD-valid zip (framing varies -> widen)
  for(long off=s1-8; off<=s1+48; off++){
    if(off<0)continue; uint8_t r[4]; for(int i=0;i<4;i++)r[i]=d[off+i]^(uint8_t)"\x50\x4b\x03\x04"[i];
    long S1=-1;
    for(uint64_t s=0;s<SEEDMAX;s++){uint32_t x=s;int ok=1;for(int i=0;i<4;i++){x=x*214013u+2531011u;if(((x>>16)&0xff)!=r[i]){ok=0;break;}}if(ok){S1=s;break;}}
    if(S1<0)continue; uint32_t x=S1; long win=n-off; if(win>7000000)win=7000000;
    for(long i=0;i<win;i++){x=x*214013u+2531011u;o[i]=d[off+i]^((x>>16)&0xff);}
    if(eocd(win)){printf("SECTION1\t0x%lx\t0x%08lx\n",off,S1);FILE*w=fopen(av[3],"wb");fwrite(o,1,win,w);fclose(w);return 0;}
  }
  printf("SECTION1_NOTFOUND\n"); return 2;
}
'''

# notable channels/SDKs to flag in the app's real dexes (mostly plaintext in the base apk under xShield)
NOTABLE = {
  'org/mozilla/javascript': 'Rhino JS engine', 'coocon': 'Coocon SASAPI (server-JS scraping)',
  'bsh/': 'BeanShell', 'ahnlab': 'AhnLab AV', 'nshc': 'NSHC',
  # PKI / crypto
  'signkorea': 'SignKorea PKI', 'yettiesoft': 'Yettiesoft PKI', 'wizvera': 'WIZVERA PKI',
  'dreamsecurity': 'DreamSecurity PKI', 'raon': 'RaonSecure', 'initech': 'INITECH', 'spongycastle': 'SpongyCastle',
  'kr/co/shift': 'Shift crypto',
  # adtech / attribution
  'appsflyer': 'AppsFlyer', 'adbrix': 'AdBrix', 'igaworks': 'IGAWorks', 'airbridge': 'Airbridge',
  'com/tnkfactory': 'TNK offerwall', 'adison': 'Adison offerwall', 'tyrads': 'TyrAds', 'adjoe': 'adjoe',
  'ironsource': 'IronSource', 'fairytech': 'Fairytech', 'unity3d': 'Unity ads',
  # telemetry
  'datadog': 'Datadog', 'sentry': 'Sentry', 'salesforce': 'Salesforce MC', 'mapbox': 'Mapbox',
}

def scan_apk_notable(apk):
    """Grep the app's real classes*.dex (plaintext under xShield) for NOTABLE channels + top roots."""
    found = {}; roots = collections.Counter()
    try: za = zipfile.ZipFile(apk)
    except Exception: return found, roots
    for n in za.namelist():
        if not re.match(r'classes\d*\.dex$', n): continue
        try: dx = za.read(n)
        except Exception: continue
        low = dx.lower()
        for k, v in NOTABLE.items():
            c = low.count(k.encode())
            if c: found[v] = found.get(v, 0) + c
        for m in re.finditer(rb'L(com|kr|net)/([a-z0-9]+)/([a-z0-9]+)/', dx):
            roots['/'.join(x.decode() for x in m.groups())] += 1
    return found, roots

def main():
    if len(sys.argv) < 2: print(__doc__); sys.exit(2)
    apk, name, data = find_base(sys.argv[1])
    if not data: print("no xShield payload asset found"); sys.exit(1)
    pkg = sys.argv[2] if len(sys.argv) > 2 else derive_pkg(apk)
    if not pkg: print("could not derive package (pass it as arg2)"); sys.exit(1)
    print(f"=== {os.path.basename(sys.argv[1])} === (pkg {pkg})")
    td = tempfile.mkdtemp(prefix='xshdec-'); assetp = os.path.join(td, 'asset.bin'); jarp = os.path.join(td, 's1.jar')
    open(assetp, 'wb').write(data)
    srcp = os.path.join(td, 'b.c'); binp = os.path.join(td, 'b')
    open(srcp, 'w').write(C)
    subprocess.run(['cc', '-O2', '-o', binp, srcp], check=True)
    r = subprocess.run([binp, assetp, pkg, jarp], capture_output=True, text=True, timeout=600)
    import hashlib
    for line in r.stdout.splitlines():
        if line.startswith('CONFIG\t'):
            fields = line.split('\t', 1)[1].split(',')
            print(f"  config: server=\033[1m{fields[-1] if fields else '?'}\033[0m  ({', '.join(fields[:4])})")
        elif line.startswith('SECTION1\t'):
            _, off, seed = line.split('\t'); print(f"  section1 jar @ {off} seed {seed}")
        elif 'NOTFOUND' in line:
            print(f"  {line} (framing differs; server may still be recovered above)")
    # component carve (best-effort; framing may differ)
    if os.path.exists(jarp):
        jb = open(jarp, 'rb').read(); e = jb.rfind(b'PK\x05\x06')
        try:
            dex = zipfile.ZipFile(io.BytesIO(jb[:e+22])).read('classes.dex')
            outdir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])) if os.path.isfile(sys.argv[1]) else sys.argv[1], 'decrypted')
            os.makedirs(outdir, exist_ok=True)
            open(os.path.join(outdir, 'component_classes.dex'), 'wb').write(dex)
            print(f"  component classes.dex: {len(dex)} B  md5 {hashlib.md5(dex).hexdigest()}  -> {outdir}/")
            print(f"  component SDK roots (xShield runtime): "
                  + ', '.join(f'{r}({c})' for r, c in _roots(dex).most_common(6)))
        except Exception as ex:
            print(f"  component zip carve failed: {ex}")
    # the real bundled-SDK inventory lives in the app's own dexes (plaintext under xShield) — always scan
    found, aroots = scan_apk_notable(apk)
    if found:
        print(f"  \033[1mNOTABLE (app dexes):\033[0m " + ', '.join(f'{v}×{c}' for v, c in sorted(found.items(), key=lambda x:-x[1])))
    print(f"  app SDK roots: " + ', '.join(f'{r}({c})' for r, c in aroots.most_common(10)))

def _roots(dex):
    r = collections.Counter()
    for m in re.finditer(rb'L([a-z][a-z0-9]+(?:/[a-z0-9_]+){1,2})/', dex): r[m.group(1).decode()] += 1
    return r

if __name__ == '__main__':
    main()
