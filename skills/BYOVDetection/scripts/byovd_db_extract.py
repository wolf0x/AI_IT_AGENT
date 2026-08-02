"""Extract minimal BYOVD hash database from loldrivers.io API."""
import json, sys, urllib.request, ssl

API_URL = "https://www.loldrivers.io/api/drivers.json"
OUTPUT = sys.argv[1] if len(sys.argv) > 1 else "byovd_db.json"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

print(f"[*] Fetching {API_URL} ...")
req = urllib.request.Request(API_URL, headers={"User-Agent": "RustAgent/0.16"})
with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
    drivers = json.loads(resp.read().decode("utf-8"))

print(f"[*] Processing {len(drivers)} driver entries...")

db = []
for drv in drivers:
    samples = drv.get("KnownVulnerableSamples") or []
    category = drv.get("Category", "vulnerable")
    mitre_id = drv.get("MitreID", "T1068")
    for s in samples:
        sha256 = (s.get("SHA256") or "").lower()
        sha1 = (s.get("SHA1") or "").lower()
        md5 = (s.get("MD5") or "").lower()
        auth = s.get("Authentihash") or {}
        auth_sha256 = (auth.get("SHA256") or "").lower()
        imphash = (s.get("Imphash") or "").lower()
        filename = s.get("OriginalFilename") or s.get("Filename") or ""
        company = s.get("Company") or ""
        product = s.get("Product") or ""
        hvci = s.get("LoadsDespiteHVCI") == "TRUE"

        if not (sha256 or auth_sha256 or imphash):
            continue

        db.append({
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "auth_sha256": auth_sha256,
            "imphash": imphash,
            "filename": filename,
            "category": category,
            "mitre_id": mitre_id,
            "company": company,
            "product": product,
            "hvci_bypass": hvci,
        })

print(f"[*] Extracted {len(db)} hash entries")

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(db, f, separators=(",", ":"), ensure_ascii=False)

import os
size_kb = os.path.getsize(OUTPUT) / 1024
print(f"[+] Database saved: {OUTPUT} ({size_kb:.1f} KB, {len(db)} entries)")
