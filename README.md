# 🔐 Audit Keamanan Web — Skill & Tools untuk Agent AI

Paket skill + arsenal tools untuk membantu agent AI (ChatGPT, Claude, dll.)
melakukan **audit keamanan aplikasi web secara defensif**: memindai, menemukan,
membuktikan, dan **memperbaiki** kerentanan pada aplikasi **milik sendiri**.

> ⚠️ **Baca [`DISCLAIMER.md`](DISCLAIMER.md) sebelum memakai.** Tools di sini hanya
> untuk sistem yang kamu miliki atau yang memberimu izin tertulis untuk diuji.
> Memindai sistem orang lain tanpa izin adalah tindakan ilegal.

---

## 📦 Isi repo

```
audit-keamanan-web/
├── README.md                     ← file ini
├── DISCLAIMER.md                 ← aturan hukum & etika (WAJIB dibaca)
├── LICENSE                       ← MIT
├── skills/
│   ├── audit-keamanan-web-codereview.md   ← audit kode sumber (white-box/SAST)
│   ├── audit-keamanan-web-blackbox.md     ← uji website hidup (black-box/DAST)
│   └── tools-keamanan-web.md              ← arsenal tools per kategori A–I
├── gpt/
│   └── custom-gpt-instructions.md         ← instruksi gabungan siap tempel ke Custom GPT
└── scripts/
    └── scanner_kustom.py                  ← template scanner Python non-destruktif
```

## 🎯 Cakupan kerentanan (A–I)

- **A. Injection** — SQLi, NoSQLi, Command Injection, LDAP/XPath/SSTI
- **B. XSS & client-side** — stored/reflected/DOM, CSP
- **C. Code execution & file** — RCE, SSRF, XXE, LFI/RFI, path traversal, deserialisasi
- **D. Auth & Authz** — IDOR, privilege escalation (horizontal/vertical), JWT, OAuth, reset/session
- **E. Business logic** — price/quantity tampering, race condition, workflow bypass, replay
- **F. Web security** — CORS, CSRF, open redirect, clickjacking, cookie flags, header
- **G. Secrets & data exposure** — API key/secret bocor, PII di log/response, endpoint debug
- **H. AI / LLM** — prompt injection lintas user, kebocoran riwayat, output menipu
- **I. User enumeration & account oracle** — kebocoran eksistensi akun

## 🚀 Cara pakai

### Opsi 1 — Custom GPT (ChatGPT)
1. ChatGPT → **Explore GPTs → Create → Configure**.
2. Tempel isi [`gpt/custom-gpt-instructions.md`](gpt/custom-gpt-instructions.md) ke kolom **Instructions**.
3. Upload [`skills/tools-keamanan-web.md`](skills/tools-keamanan-web.md) ke bagian **Knowledge**.
4. Aktifkan **Web Browsing** dan **Code Interpreter**.

### Opsi 2 — Claude / agent lain
Pasang file di `skills/` sebagai skill, atau tempel sebagai system prompt.

### Opsi 3 — Manual
Jalankan tools dari [`skills/tools-keamanan-web.md`](skills/tools-keamanan-web.md) di
terminal (Kali/Parrot/WSL/Docker), lalu tempel output ke AI untuk ditafsirkan,
diverifikasi, dan disusun jadi laporan + perbaikan.

## ⚙️ Catatan penting

- **AI tidak menjalankan tools secara langsung ke target eksternal.** ChatGPT & sejenisnya
  bersandbox tanpa akses jaringan bebas. Alur realistis: **kamu** jalankan tool di mesinmu,
  AI menafsirkan hasilnya. File skill sudah menulis alur ini.
- **Mode non-destruktif.** Jangan pakai payload yang menghapus/mengubah data, brute force
  masif, atau DoS. PoC hanya untuk pembuktian.
- **Aplikasi dengan data sensitif (mis. kesehatan/pasien):** uji di staging/salinan dulu,
  bukan produksi.

## 📋 Format laporan temuan

```
[SEVERITY] | FILE:LINE atau URL | CWE-xxx | PoC singkat | FIX ringkas
```

## 📜 Lisensi
MIT — lihat [`LICENSE`](LICENSE).
