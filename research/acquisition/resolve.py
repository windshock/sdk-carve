#!/usr/bin/env python3
"""Multi-source APK resolver — package(+version) -> artifact, normalized + verified.

Design (PLAN Track 2 "Corpus acquisition — NOT AndroZoo-gated"): don't reimplement downloaders;
orchestrate existing ones behind one interface and normalize/verify the result. Corpus acquisition
for the "malicious SDK in a real host app + infected->clean version boundary" case is *not*
AndroZoo-gated (that is how the Necro hosts + DMB-TV versions were already obtained).

Fallback chain:  local -> androzoo -> apkmirror -> apkcombo -> apkpure -> play -> uptodown

What is implemented offline (runs now, no network):
  * sha256 of an APK
  * signer certificate SHA-256 (keytool, openssl fallback)  -> provenance / repackaging check
  * local-corpus lookup + normalized-record emission

Network adapters are declared with the *exact* external command and are executed ONLY with
--allow-download (auth gate, per AGENTS.md). Without it, the resolver prints the command it *would*
run (dry-run). Callers must respect each source's ToS and verify signer+hash (mirror APKs may be
repackaged).
"""
from __future__ import annotations
import argparse, dataclasses, hashlib, json, os, re, shutil, subprocess, sys, time, zipfile

# ------------------------- normalized record -------------------------
@dataclasses.dataclass
class Artifact:
    package: str
    version_name: str | None = None
    version_code: int | None = None
    sha256: str | None = None
    signer_sha256: str | None = None
    source: str | None = None
    source_url: str | None = None
    split: bool = False
    path: str | None = None
    retrieved_at: str | None = None
    def json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2, ensure_ascii=False)

# ------------------------- offline verification -------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def signer_sha256(path: str) -> str | None:
    """SHA-256 of the (first) signing certificate — stable across versions of the same signer."""
    kt = shutil.which("keytool")
    if kt:
        try:
            out = subprocess.run([kt, "-printcert", "-jarfile", path], capture_output=True,
                                 text=True, timeout=120).stdout
            m = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", out)
            if m:
                return m.group(1).replace(":", "").lower()
        except Exception:
            pass
    # fallback: extract the DER cert from META-INF and openssl-digest it
    op = shutil.which("openssl")
    if op:
        try:
            with zipfile.ZipFile(path) as z:
                cert = next((n for n in z.namelist()
                             if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)), None)
                if cert:
                    der = z.read(cert)
                    p = subprocess.run([op, "pkcs7", "-inform", "DER", "-print_certs", "-outform", "DER"],
                                       input=der, capture_output=True, timeout=60)
                    if p.returncode == 0 and p.stdout:
                        return hashlib.sha256(p.stdout).hexdigest()
        except Exception:
            pass
    return None

def apk_ident(path: str) -> tuple[str | None, str | None, int | None]:
    """(package, version_name, version_code) via aapt if available, else (None,...)."""
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        try:
            cmd = [aapt, "dump", "badging", path] if aapt.endswith("aapt") else [aapt, "dump", "badging", path]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
            pkg = re.search(r"package: name='([^']+)'", out)
            vn = re.search(r"versionName='([^']*)'", out)
            vc = re.search(r"versionCode='([0-9]+)'", out)
            return (pkg.group(1) if pkg else None,
                    vn.group(1) if vn else None,
                    int(vc.group(1)) if vc else None)
        except Exception:
            pass
    return (None, None, None)

def verify(path: str, package: str, expect_sha: str | None = None,
           expect_signer: str | None = None, source: str = "local") -> Artifact:
    pkg, vn, vc = apk_ident(path)
    a = Artifact(package=pkg or package, version_name=vn, version_code=vc,
                 sha256=sha256_file(path), signer_sha256=signer_sha256(path),
                 source=source, path=os.path.abspath(path),
                 split=path.endswith((".xapk", ".apks")),
                 retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if expect_sha and a.sha256 != expect_sha.lower():
        raise SystemExit(f"[verify] sha256 mismatch: got {a.sha256} expected {expect_sha}")
    if expect_signer and a.signer_sha256 and a.signer_sha256 != expect_signer.lower():
        raise SystemExit(f"[verify] signer mismatch (repackaged?): got {a.signer_sha256} expected {expect_signer}")
    return a

# ------------------------- source adapters (network; gated) -------------------------
# Each adapter declares an argv TEMPLATE (list) — never a shell string — so package/version can
# never be interpreted as shell metacharacters. Executed only with --allow-download, and only after
# package/version pass strict validation below. Note the apkpure adapter passes package/version as
# positional argv to `python3 -c`, NOT interpolated into the code string.
VALID_PKG = re.compile(r"^[A-Za-z0-9_.]+$")
VALID_VER = re.compile(r"^[A-Za-z0-9_.+-]*$")
_AZKEY = "@ANDROZOO_APIKEY@"  # replaced (not shell-expanded) with the env value at run time

ADAPTERS = {
    "androzoo":  {"env": "ANDROZOO_APIKEY", "bin": "curl",
                  "argv": ["curl", "-fL", "-G", "--data-urlencode", "apikey=" + _AZKEY,
                           "--data-urlencode", "sha256={sha}",
                           "https://androzoo.uni.lu/api/download", "-o", "{out}"],
                  "note": "needs sha256 (from AndroZoo metadata by package/version); best for citable/reproducible corpus"},
    "apkmirror": {"bin": "npx",
                  "argv": ["npx", "apkmirror-downloader", "--org", "{org}", "--repo", "{repo}",
                           "--version", "{version}", "--out", "{out}"],
                  "note": "APKMirror history; Cloudflare — github tanishqmanuja/apkmirror-downloader"},
    "apkcombo":  {"bin": "npx",
                  "argv": ["npx", "@nirewen/apkcombo-downloader", "--package", "{package}",
                           "--version", "{version}", "--out", "{out}"],
                  "note": "APKCombo history; good fallback for APKMirror Cloudflare"},
    "apkpure":   {"pip": "apkpure", "bin": "python3",
                  "argv": ["python3", "-c",
                           "import apkpure,sys; apkpure.download(sys.argv[1], version=sys.argv[2])",
                           "{package}", "{version}"],
                  "note": "get_versions()+download(); Python-native (used for Necro/DMB-TV)"},
    "play":      {"bin": "gpapi-download",
                  "argv": ["gpapi-download", "--package", "{package}", "--version-code", "{version}"],
                  "note": "Google Play is NOT an archive — only if Google still hosts that versionCode"},
    "uptodown":  {"bin": "uptodown-dl",
                  "argv": ["uptodown-dl", "{package}", "{version}"],
                  "note": "full archive; scraper, less stable"},
}

def adapter_available(name: str) -> bool:
    a = ADAPTERS[name]
    if "env" in a and not os.environ.get(a["env"]):
        return False
    if "pip" in a:
        try: __import__(a["pip"])
        except Exception: return False
    return shutil.which(a["bin"]) is not None

# ------------------------- resolve -------------------------
DEFAULT_ORDER = ["local", "androzoo", "apkmirror", "apkcombo", "apkpure", "play", "uptodown"]

def local_lookup(package: str, version: str | None, corpus: str) -> str | None:
    if not os.path.isdir(corpus): return None
    for root, _, files in os.walk(corpus):
        for fn in files:
            if fn.endswith((".apk", ".xapk", ".apks")) and package.split(".")[-1].lower() in fn.lower():
                if version is None or version in fn:
                    return os.path.join(root, fn)
    return None

def resolve(package: str, version: str | None, order: list[str], corpus: str,
            allow_download: bool, out_dir: str) -> Artifact | None:
    import shlex
    if not VALID_PKG.match(package):
        raise SystemExit(f"[resolve] invalid package (allowed: A-Za-z0-9_.): {package!r}")
    if version is not None and not VALID_VER.match(version):
        raise SystemExit(f"[resolve] invalid version (allowed: A-Za-z0-9_.+-): {version!r}")
    fields = dict(package=package, version=version or "", org=package,
                  repo=package.split(".")[-1], sha="<sha256-from-metadata>",
                  out=os.path.join(out_dir, f"{package}-{version or 'latest'}.apk"))
    for src in order:
        if src == "local":
            p = local_lookup(package, version, corpus)
            if p:
                print(f"[local] hit: {p}", file=sys.stderr)
                return verify(p, package, source="local")
            continue
        if not adapter_available(src):
            print(f"[{src}] unavailable (missing key/tool) — skip", file=sys.stderr); continue
        # build argv WITHOUT a shell; each element is templated then value-substituted
        argv = [os.environ.get("ANDROZOO_APIKEY", "").join(el.split(_AZKEY)) if _AZKEY in el
                else el.format(**fields) for el in ADAPTERS[src]["argv"]]
        if not allow_download:
            print(f"[{src}] DRY-RUN (auth gate; --allow-download to run): "
                  + " ".join(shlex.quote(x) for x in argv), file=sys.stderr); continue
        print(f"[{src}] RUN (no shell): {argv}", file=sys.stderr)
        rc = subprocess.run(argv).returncode  # shell=False — package/version cannot inject
        out = fields["out"]
        if rc == 0 and os.path.exists(out):
            return verify(out, package, source=src)
    return None

def main() -> None:
    ap = argparse.ArgumentParser(description="Multi-source APK resolver (package[+version] -> verified artifact)")
    ap.add_argument("package")
    ap.add_argument("--version", default=None)
    ap.add_argument("--order", default=",".join(DEFAULT_ORDER))
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus"))
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__), "corpus"))
    ap.add_argument("--allow-download", action="store_true", help="actually invoke network adapters (auth-gated; respect ToS)")
    ap.add_argument("--verify-only", metavar="APK", help="just verify an existing APK (sha256 + signer)")
    args = ap.parse_args()
    if args.verify_only:
        print(verify(args.verify_only, args.package, source="local").json()); return
    os.makedirs(args.out_dir, exist_ok=True)
    art = resolve(args.package, args.version, args.order.split(","), args.corpus,
                  args.allow_download, args.out_dir)
    if art: print(art.json())
    else: raise SystemExit(f"[resolve] no source produced {args.package} {args.version or ''}")

if __name__ == "__main__":
    main()
