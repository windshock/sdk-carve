#!/usr/bin/env python3
"""Review follow-up: identify an un-enumerated root and inventory what it touches / where it sends.

Static, read-only. Per package root in a dex2jar JAR, extracts:
  - distinct hosts / URLs (plaintext; obfuscated SDKs may hide these)
  - sensitive-capability API references actually present (identity/location/applist/contacts/...)
  - ContactsContract discriminator: photo-loading (benign) vs bulk contact data (Phone/Email/data1)
  - webview / network / crypto / dynamic-loading / reflection presence

Usage: endpoint-inventory.py <app.jar> <root/prefix> [<root/prefix> ...]
"""
import re, sys, zipfile
from collections import defaultdict

HOST = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,120}")
DOMAIN = re.compile(rb"\b[a-z0-9](?:[a-z0-9-]{0,40}\.){1,4}(?:com|net|co\.kr|kr|io|be|xyz|me|org|dev|app|ai|cn)\b")
CAPS = {
    "gaid":     [b"AdvertisingIdClient", b"getAdvertisingIdInfo", b"advertising_id"],
    "imei/devid":[b"getDeviceId", b"getImei", b"getSubscriberId", b"getSimSerialNumber"],
    "androidid":[b"getString\x00", b"android_id", b"Secure;->getString"],
    "location": [b"requestLocationUpdates", b"getLastKnownLocation", b"getCurrentLocation"],
    "wifi/bt":  [b"getScanResults", b"getBondedDevices", b"getBSSID", b"getSSID", b"startLeScan"],
    "applist":  [b"getInstalledPackages", b"getInstalledApplications", b"getRunningTasks", b"queryIntentActivities"],
    "contacts": [b"ContactsContract", b"content://com.android.contacts", b"content://contacts"],
    "sms/call": [b"content://sms", b"CallLog", b"sendTextMessage"],
    "clipboard":[b"getPrimaryClip"],
    "usagestats":[b"UsageStatsManager", b"queryUsageStats"],
    "accessibility":[b"AccessibilityService"],
    "webview":  [b"loadUrl", b"evaluateJavascript", b"addJavascriptInterface", b"postUrl"],
    "net":      [b"Lokhttp3/", b"Lretrofit2/", b"openConnection", b"Ljava/net/Socket;"],
    "crypto":   [b"Ljavax/crypto/Cipher", b"Landroid/util/Base64"],
    "dynload":  [b"DexClassLoader", b"InMemoryDexClassLoader"],
    "reflect":  [b"getDeclaredMethod", b"getMethod", b"forName"],
}
# ContactsContract discriminator
CONTACT_PHOTO = [b"Photo", b"openContactPhotoInputStream", b"photo_uri", b"CONTENT_URI\x00"]
CONTACT_BULK  = [b"CommonDataKinds", b"has_phone_number", b"display_name", b"data1", b"Phone;", b"Email;", b"Contacts$Data"]

def inv(jar, root):
    hosts=set(); caps=defaultdict(int); ncls=0
    photo=set(); bulk=set(); contact_cls=set()
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if not (name.endswith(".class") and name.startswith(root)): continue
            ncls+=1; b=z.read(name)
            for h in HOST.findall(b): hosts.add(h.decode("latin-1"))
            for dmn in DOMAIN.findall(b): hosts.add(dmn.decode("latin-1"))
            for cap,pats in CAPS.items():
                if any(p in b for p in pats): caps[cap]+=1
            if b"ContactsContract" in b or b"content://com.android.contacts" in b:
                contact_cls.add(name)
                if any(p in b for p in CONTACT_PHOTO): photo.add(name)
                if any(p in b for p in CONTACT_BULK):  bulk.add(name)
    print(f"\n### root={root}  classes={ncls}")
    caps_s=" ".join(f"{k}:{v}" for k,v in sorted(caps.items(), key=lambda x:-x[1]))
    print(f"  caps: {caps_s or '(none plaintext)'}")
    h=sorted(x for x in hosts if not x.endswith((".png",".jpg",".gif",".css",".js")))
    print(f"  hosts({len(h)}): " + (", ".join(h[:40]) if h else "(none plaintext — likely obfuscated)"))
    if contact_cls:
        print(f"  CONTACTS: {len(contact_cls)} class(es); photo-context={len(photo)} bulk-context={len(bulk)}")
        for c in sorted(contact_cls)[:6]: print(f"     - {c}")

jar=sys.argv[1]
for root in sys.argv[2:]:
    inv(jar, root)
