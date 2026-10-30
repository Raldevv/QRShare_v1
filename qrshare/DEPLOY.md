# QRShare on Vercel — free, secure, step by step

Everything below is on free plans: **Vercel** (hosting) + **Neon** (database) + **Cloudinary** (file storage).

## 0. Do this first (5 minutes)
1. **Rotate your Cloudinary API secret** (Cloudinary Dashboard → Settings → API Keys → generate a new key/secret).
   The old secret was written inside `app.py`, so treat it as leaked.
2. Never put keys in code again. This project reads them only from environment variables.

## 1. Put the project on GitHub
Create a **private** GitHub repo and upload this folder (the `.gitignore` already blocks `.env`).
Copy your old `static/fonts/` folder into `public/static/fonts/` (the two ComicNeue `.otf` files).

## 2. Create the free database (Neon)
1. Sign up at neon.com (no credit card). Create a project.
2. Copy the **pooled** connection string (the host contains `-pooler`). This is your `DATABASE_URL`.
3. Nothing else to do — QRShare creates its own tables on first start.

## 3. Deploy on Vercel
1. vercel.com → **Add New → Project** → import your GitHub repo. Framework: *Other/Flask* (auto-detected).
2. Before pressing Deploy, open **Environment Variables** and add everything from `.env.example`:
   `SECRET_KEY`, `DATABASE_URL`, `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`,
   `PUBLIC_BASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `REGISTRATION_CODE`.
   - Make a SECRET_KEY with: `python -c "import secrets; print(secrets.token_hex(32))"`
   - `PUBLIC_BASE_URL` = the address Vercel gives you (e.g. `https://qrshare.vercel.app`). If you only know it
     after the first deploy, add it then and redeploy.
3. Deploy. Log in with your `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Faculty register at `/register` using the invite code.

## 4. Check Cloudinary once (optional but recommended)
```
pip install -r requirements.txt
export CLOUDINARY_CLOUD_NAME=... CLOUDINARY_API_KEY=... CLOUDINARY_API_SECRET=...
python scripts/check_cloudinary.py
```
All lines should say PASS.

## 5. Re-run the security tests any time
```
python scripts/selftest.py        # 65 checks, works offline
```

## Free-tier limits to know
- **Files max 10 MB** (Cloudinary free plan). Set `MAX_UPLOAD_MB` lower if you want.
- Neon free: 0.5 GB database, sleeps after 5 idle minutes (first click after a pause takes about a second).
- Vercel Hobby is intended for personal / non-commercial use, which fits a capstone. Check Vercel's current terms.

## What changed from the PythonAnywhere version
| Area | Before | Now |
|---|---|---|
| Secrets | In `app.py` | Environment variables only |
| Files | Public Cloudinary URL (reusable forever) | Private; 60-second signed URL per download |
| Burn-after-reading | GET link (crawlers could burn it) | POST button + signed confirm token, atomic SQL burn |
| Share tokens | Stored as plain text | SHA-256 hash only, 192-bit random |
| Admin | Anyone could register `admin` | Role in database; bootstrap from env; reserved names |
| Login | Unlimited guesses | 5 tries / 15 min per account, DB-backed (works on serverless) |
| Uploads | Through Flask (breaks above 4.5 MB on Vercel) | Browser → Cloudinary (signed), server verifies real content |
| Content checks | Header bytes only | PDF/Image/ZIP/OOXML structure, macro, script and ZIP-bomb checks |
| Headers | None | CSP with nonces, nosniff, no-referrer, frame-deny, HSTS |
| Audit | None | Access log (hashed source IDs) visible to admin |
| Database | SQLite file | Neon Postgres |
