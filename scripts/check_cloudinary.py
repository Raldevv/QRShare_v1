"""
Live check of your Cloudinary setup (run ONCE after setting the env variables).

    export CLOUDINARY_CLOUD_NAME=... CLOUDINARY_API_KEY=... CLOUDINARY_API_SECRET=...
    python scripts/check_cloudinary.py

It uploads a tiny private file, proves the public URL is blocked, proves the
signed 60-second URL works, proves an expired signed URL is refused, then cleans up.
"""
import os, sys, time, uuid, urllib.request, urllib.error
import cloudinary, cloudinary.uploader, cloudinary.utils

cloudinary.config(cloud_name=os.environ["CLOUDINARY_CLOUD_NAME"], api_key=os.environ["CLOUDINARY_API_KEY"],
                  api_secret=os.environ["CLOUDINARY_API_SECRET"], secure=True)
BODY = b"qrshare live check " + uuid.uuid4().bytes
pid = f"qrshare_vault/selfcheck-{uuid.uuid4()}/check.txt"

def status(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "check"}), timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""

ok = True
def report(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name, extra)

cloudinary.uploader.upload(BODY, public_id=pid, resource_type="raw", type="authenticated")
report("upload as private/authenticated asset", True)
pub = f"https://res.cloudinary.com/{cloudinary.config().cloud_name}/raw/upload/{pid}"
code, _ = status(pub)
report("public URL is NOT readable", code != 200, f"(HTTP {code})")
good = cloudinary.utils.private_download_url(pid, "txt", resource_type="raw", type="authenticated",
                                              attachment=True, expires_at=int(time.time()) + 60)
code, data = status(good)
report("signed 60s URL downloads the file", code == 200 and data == BODY, f"(HTTP {code})")
stale = cloudinary.utils.private_download_url(pid, "txt", resource_type="raw", type="authenticated",
                                               attachment=True, expires_at=int(time.time()) - 30)
code, _ = status(stale)
report("expired signed URL is refused", code != 200, f"(HTTP {code})")
cloudinary.uploader.destroy(pid, resource_type="raw", type="authenticated", invalidate=True)
print("\nALL GOOD" if ok else "\nSomething failed - send me this output and I'll fix it.")
sys.exit(0 if ok else 1)
