"""
Offline self-test for QRShare (no internet, no Cloudinary account needed).

    python scripts/selftest.py

Uses a throw-away SQLite file and replaces the Cloudinary network calls with
stand-ins, then checks the security controls end to end. Useful evidence for
the "Testing" section of Chapter 3.
"""
import io
import os
import re
import struct
import sys
import tempfile
import zlib
import zipfile

os.environ.update({
    "SECRET_KEY": "test-secret-key-for-selftest-only-0123456789",
    "SQLITE_PATH": os.path.join(tempfile.mkdtemp(), "t.db"),
    "CLOUDINARY_CLOUD_NAME": "democloud", "CLOUDINARY_API_KEY": "123", "CLOUDINARY_API_SECRET": "shh",
    "ADMIN_USERNAME": "prof_admin", "ADMIN_PASSWORD": "AdminPass-12345",
    "REGISTRATION_CODE": "FACULTY-2026",
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as qr  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {extra}")


# ---- stand-ins for Cloudinary --------------------------------------------------
STORE = {}
PURGED = []
qr.fetch_asset_bytes = lambda public_id, ext, limit: STORE[public_id][: limit + 1]
qr.purge_cloud_file = lambda public_id: PURGED.append(public_id)


def tiny_png():
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = zlib.compress(b"\x00\xff\x00\x00")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


def docx_bytes(macro=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        if macro:
            z.writestr("word/vbaProject.bin", b"x")
    return buf.getvalue()



def Q(sql, params=()):
    """Run a read query against whichever database the app is using."""
    d = qr.DB()
    try:
        return [dict(r) for r in d.execute(sql, params).fetchall()]
    finally:
        d.close()


def X(sql, params=()):
    d = qr.DB()
    try:
        d.execute(sql, params)
        d.commit()
    finally:
        d.close()


client = qr.app.test_client()


def token_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def csrf(path="/login"):
    return token_from(client.get(path).get_data(as_text=True))


print("\n[1] Content verification (anti-spoofing)")
v = qr.verify_file_content
check("real PDF accepted", v("pdf", b"%PDF-1.4\n%%EOF")[0])
check("EXE renamed .pdf rejected", not v("pdf", b"MZ\x90\x00 fake exe")[0])
check("PDF with JavaScript rejected", not v("pdf", b"%PDF-1.4 /JavaScript (app.alert(1))")[0])
check("real PNG accepted", v("png", tiny_png())[0])
check("PNG bytes named .jpg rejected", not v("jpg", tiny_png())[0])
check("HTML named .png rejected", not v("png", b"<html><script>alert(1)</script></html>")[0])
check("real DOCX accepted", v("docx", docx_bytes())[0])
check("DOCX with macro rejected", not v("docx", docx_bytes(macro=True))[0])
check("plain ZIP named .docx rejected", not v("docx", (lambda b: (zipfile.ZipFile(b, "w").writestr("a.txt", "x"), b.getvalue())[1])(io.BytesIO()))[0])
check("binary named .txt rejected", not v("txt", b"abc\x00def")[0])
check("empty file rejected", not v("pdf", b"")[0])
bomb = io.BytesIO()
with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("big.bin", b"\x00" * (60 * 1024 * 1024))
check("ZIP bomb rejected", not v("zip", bomb.getvalue())[0])
check("extension whitelist blocks .exe/.html/.php", all(qr.allowed_extension(n) is None for n in ["a.exe", "a.html", "a.php", "a.svg", "noext"]))

print("\n[2] Authentication & access control")
r = client.get("/")
check("anonymous redirected to /welcome", r.status_code == 302 and "/welcome" in r.location)
r = client.get("/api/folder/x/contents")
check("anonymous API gets 401 JSON", r.status_code == 401)
r = client.post("/register", data={"username": "alice", "password": "CorrectHorse-99", "invite_code": "FACULTY-2026"})
check("register without CSRF token blocked", r.status_code == 400)
tok = csrf("/register")
r = client.post("/register", data={"csrf_token": tok, "username": "admin", "password": "CorrectHorse-99", "invite_code": "FACULTY-2026"})
check("cannot register reserved name 'admin'", b"reserved" in r.data)
r = client.post("/register", data={"csrf_token": tok, "username": "prof_admin", "password": "CorrectHorse-99", "invite_code": "FACULTY-2026"})
check("cannot register the bootstrap admin name", b"reserved" in r.data)
r = client.post("/register", data={"csrf_token": tok, "username": "alice", "password": "CorrectHorse-99", "invite_code": "WRONG"})
check("wrong invite code rejected", b"invite code" in r.data)
r = client.post("/register", data={"csrf_token": tok, "username": "alice", "password": "short", "invite_code": "FACULTY-2026"})
check("short password rejected", b"Password must be" in r.data)
r = client.post("/register", data={"csrf_token": tok, "username": "alice", "password": "CorrectHorse-99", "invite_code": "FACULTY-2026"})
check("valid registration succeeds", r.status_code == 302)
client.post("/register", data={"csrf_token": csrf("/register"), "username": "bob", "password": "AnotherStrong-77", "invite_code": "FACULTY-2026"})
client.post("/register", data={"csrf_token": csrf("/register"), "username": "carol", "password": "ThirdStrong-4242", "invite_code": "FACULTY-2026"})

print("\n[3] Login throttling")
c2 = qr.app.test_client()
t2 = token_from(c2.get("/login").get_data(as_text=True))
codes = []
for _ in range(7):
    codes.append(c2.post("/login", data={"csrf_token": t2, "username": "carol", "password": "wrong-pass-123"}).status_code)
check("account locks after 5 failures (429)", codes[:5] == [200] * 5 and 429 in codes[5:], str(codes))
r = c2.post("/login", data={"csrf_token": t2, "username": "carol", "password": "ThirdStrong-4242"})
check("correct password also blocked while locked", r.status_code == 429)

print("\n[4] Upload pipeline (sign -> verify)")
r = client.post("/login", data={"csrf_token": csrf("/login"), "username": "alice", "password": "CorrectHorse-99"})
check("login succeeds", r.status_code == 302)
r = client.get("/", follow_redirects=True)
html = r.get_data(as_text=True)
folder_id = re.search(r'/folder/([0-9a-f-]{36})', r.request.path).group(1)
hdr = {"X-CSRFToken": token_from(html)}
check("CSP header present with nonce", "nonce-" in r.headers.get("Content-Security-Policy", ""))
check("clickjacking/nosniff/referrer headers", r.headers.get("X-Frame-Options") == "DENY"
      and r.headers.get("X-Content-Type-Options") == "nosniff" and r.headers.get("Referrer-Policy") == "no-referrer")
check("inline scripts carry the CSP nonce", 'nonce="' in html)
check("no secrets in HTML", "shh" not in html)

def sign(name, size, **kw):
    return client.post("/api/upload/sign", json={"parent_id": folder_id, "filename": name, "size": size,
                                                  "duration": kw.get("duration", "1"), "uses": kw.get("uses", "1")}, headers=hdr)

check("sign without CSRF header blocked", client.post("/api/upload/sign", json={}).status_code == 400)
check(".exe refused at sign time", sign("virus.exe", 1000).status_code == 400)
check("oversize refused at sign time", sign("big.pdf", qr.MAX_UPLOAD_BYTES + 1).status_code == 400)
check("other user's folder refused", client.post("/api/upload/sign", json={"parent_id": "nope", "filename": "a.pdf", "size": 10}, headers=hdr).status_code == 403)

s = sign("Quiz Reviewer.pdf", 100)
j = s.get_json()
check("sign returns signed, private upload params", s.status_code == 200 and j["fields"]["type"] == "authenticated" and "signature" in j["fields"])
import cloudinary.utils as cu  # noqa: E402
p = {k: j["fields"][k] for k in ("public_id", "timestamp", "type")}
check("signature verifies against API secret", cu.api_sign_request(p, "shh") == j["fields"]["signature"])
check("API secret never sent to browser", "shh" not in s.get_data(as_text=True))

STORE[j["fields"]["public_id"]] = b"MZ\x90\x00 pretend this is an exe"
r = client.post("/api/upload/finalize", json={"upload_id": j["upload_id"]}, headers=hdr)
check("spoofed PDF rejected at finalize", r.status_code == 400 and j["fields"]["public_id"] in PURGED)

j2 = sign("Quiz Reviewer.pdf", 100).get_json()
STORE[j2["fields"]["public_id"]] = b"%PDF-1.4\n%%EOF"
r = client.post("/api/upload/finalize", json={"upload_id": j2["upload_id"]}, headers=hdr)
check("genuine PDF accepted at finalize", r.status_code == 200 and r.get_json()["success"])
r = client.get(f"/folder/{folder_id}")
html = r.get_data(as_text=True)
m = re.search(r'value="(https?://[^"]+/share/([A-Za-z0-9_-]+))"', html)
check("QR panel shown once after upload (PRG)", m is not None and "data:image/png;base64" in html)
link, token = m.group(1), m.group(2)
check("refresh does not show it again", "/share/" not in client.get(f"/folder/{folder_id}").get_data(as_text=True).split("generated-link")[0] or
      re.search(r'value="https?://[^"]+/share/', client.get(f"/folder/{folder_id}").get_data(as_text=True)) is None)

print("\n[5] Share tokens, crawler safety, atomic burn")
db_rows = Q("SELECT token_hash FROM shares")
check("raw token not stored (only SHA-256 hash)", all(token not in h["token_hash"] and len(h["token_hash"]) == 64 for h in db_rows))
anon = qr.app.test_client()
page = anon.get(f"/share/{token}")
check("student landing page loads", page.status_code == 200 and b"Download File" in page.data)
conf = re.search(r'name="confirm" value="([^"]+)"', page.get_data(as_text=True)).group(1)
anon.get(f"/share/{token}"); anon.get(f"/share/{token}")
check("repeated GET (crawler/preview) does not burn", anon.get(f"/api/share/status/{token}").get_json()["active"] is True)
check("GET on download endpoint not allowed", anon.get(f"/share/{token}/download").status_code == 405)
r = anon.post(f"/share/{token}/download", data={"confirm": "forged"})
check("forged confirm token does not burn", r.status_code == 302 and anon.get(f"/api/share/status/{token}").get_json()["active"] is True)
r = anon.post(f"/share/{token}/download", data={"confirm": conf})
check("real download: 303 to expiring signed URL", r.status_code == 303 and "expires_at=" in r.location and "signature=" in r.location, r.location if r.status_code == 303 else r.status_code)
check("URL is not a public/permanent CDN link", "res.cloudinary.com" not in r.location and "/raw/download" in r.location)
check("token burned after first download", anon.get(f"/api/share/status/{token}").get_json() == {"active": False, "reason": "burned"})
r = anon.post(f"/share/{token}/download", data={"confirm": conf})
check("second download denied", r.status_code == 302 and "/share/" in r.location)
check("burned page returns 410", anon.get(f"/share/{token}").status_code == 410)
check("unknown token returns 404", anon.get("/share/" + "A" * 32).status_code == 404)
check("dashboard badge says Burned", b"Burned" in client.get(f"/folder/{folder_id}").data)

print("\n[6] Expiry")
fid = Q("SELECT id FROM items WHERE type='file'")[0]["id"]
r = client.post(f"/api/item/share/{fid}", data={"csrf_token": hdr["X-CSRFToken"], "duration": "1", "uses": "unli"})
tk = r.get_json()["link"].rsplit("/", 1)[1]
X("UPDATE shares SET expires_at = '2000-01-01T00:00:00+00:00' WHERE token_hash = ?", (qr.hash_token(tk),))
check("expired link reports expired", anon.get(f"/api/share/status/{tk}").get_json()["reason"] == "expired")
page = anon.get(f"/share/{tk}")
check("expired landing page returns 410", page.status_code == 410)

print("\n[7] Cross-user isolation & admin role")
bob = qr.app.test_client()
bob.post("/login", data={"csrf_token": token_from(bob.get("/login").get_data(as_text=True)), "username": "bob", "password": "AnotherStrong-77"})
check("bob cannot open alice's folder", bob.get(f"/folder/{folder_id}").status_code == 403)
check("bob cannot download alice's file", bob.get(f"/download/{fid}").status_code == 404)
check("bob cannot create share for alice's file", bob.post(f"/api/item/share/{fid}", data={"csrf_token": "x"}).status_code in (400, 404))
check("bob cannot trash alice's file", (bob.post(f"/item/trash/{fid}", data={"csrf_token": token_from(bob.get('/virtual/trash').get_data(as_text=True))}).status_code in (302,)
       and Q("SELECT deleted_at FROM items WHERE id=?", (fid,))[0]["deleted_at"] is None))
check("non-admin blocked from /admin", bob.get("/admin").status_code == 403)
check("logout via GET not allowed", bob.get("/logout").status_code == 405)
adm = qr.app.test_client()
r = adm.post("/login", data={"csrf_token": token_from(adm.get("/login").get_data(as_text=True)), "username": "prof_admin", "password": "AdminPass-12345"})
check("bootstrap admin can log in", r.status_code == 302)
page = adm.get("/admin")
check("admin panel + audit log render", page.status_code == 200 and b"Audit Log" in page.data and b"share_download" in page.data)

print("\n[8] Owner file lifecycle")
t = token_from(client.get(f"/folder/{folder_id}").get_data(as_text=True))
check("owner download -> expiring signed URL", client.get(f"/download/{fid}").status_code == 303)
client.post(f"/item/trash/{fid}", data={"csrf_token": t})
check("trashed file no longer shareable", anon.get(f"/share/{token}").status_code in (404, 410))
client.post(f"/item/delete_forever/{fid}", data={"csrf_token": t})
check("delete forever purges cloud asset", j2["fields"]["public_id"] in PURGED)
check("trash on bogus id does not crash", client.post("/item/trash/does-not-exist", data={"csrf_token": t}).status_code == 302)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
