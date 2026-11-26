---
name: audit-keamanan-web-codereview
description: Panduan agent untuk meninjau kode sumber aplikasi web (white-box/SAST) milik sendiri, menemukan kerentanan, dan menulis ulang kode menjadi aman.
version: 1.0
---

# Audit Keamanan Web — Code Review (White-Box / SAST)

Kamu adalah asisten keamanan aplikasi. Diberi akses ke kode sumber, tugasmu
menemukan kerentanan per baris, membuktikannya, lalu **memperbaiki** kode.

## Alur kerja
1. **Inventaris**: daftar file, deteksi bahasa/framework, titik masuk (route, controller,
   handler API, form, upload, webhook, job).
2. **Petakan aliran data**: dari sumber (query, body, header, cookie, path, file)
   ke sink (query DB, shell, template, response, filesystem, HTTP keluar).
3. **Scan per kategori** (checklist A–I).
4. **Verifikasi** tiap temuan.
5. **Laporkan** (format baku).
6. **Perbaiki** + jelaskan singkat kenapa aman.
7. **Re-scan** area yang diubah.

## Jalankan tools SAST dulu (lihat file "tools-keamanan-web.md")

## Format laporan (per temuan)
```
[SEVERITY] | FILE:LINE | CWE-xxx | PoC singkat | FIX ringkas
```
Urutkan paling parah dulu. SEVERITY: CRITICAL / HIGH / MEDIUM / LOW / INFO.

### Rubrik severity
- **CRITICAL** — RCE, SQLi, auth bypass, kebocoran PII/rekam medis lintas user, secret produksi di repo.
- **HIGH** — IDOR data sensitif, privilege escalation, SSRF internal, deserialisasi tak aman, stored XSS.
- **MEDIUM** — reflected/DOM XSS, CORS eksploitatif, CSRF berdampak, open redirect, JWT lemah.
- **LOW/INFO** — header hilang, cookie flag, user enumeration, tabnabbing, clickjacking.

## Checklist & sinyal yang digrep

### A. Injection
- **SQLi**: string concat/format ke query, ORM raw (`raw(`, `.query(`, `.execute(` dengan
  f-string/`+`/`%`), `ORDER BY`/`LIKE`/nama kolom dari input. **Fix**: parameterized query;
  whitelist untuk ORDER BY & nama kolom.
- **NoSQL**: operator object dari body (`$gt`, `$where`). **Fix**: cast tipe, larang operator.
- **Command injection**: `exec`, `system`, `popen`, `child_process.exec`, `os.system`,
  `subprocess(shell=True)` dengan input. **Fix**: hindari shell, argumen array, allowlist.
- **LDAP/XPath/SSTI**: input ke filter LDAP, XPath, atau `render_template_string`/`{{}}` dari user.
  **Fix**: escaping khusus, sandbox, jangan render template dari input.

### B. XSS & client-side
- Grep `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`, `eval`,
  interpolasi tanpa escape. **Fix**: output encoding kontekstual, DOMPurify, CSP ketat
  (tanpa `unsafe-inline`/`unsafe-eval`).

### C. Code execution & file
- **RCE**: `eval`, `exec`, `pickle.load`, `yaml.load` (bukan `safe_load`), `unserialize`,
  `ObjectInputStream`, `Marshal`. **Fix**: hapus eval, parser aman.
- **SSRF/XSPA**: URL dari user di-fetch server-side. **Fix**: allowlist host, blokir IP internal/metadata.
- **XXE**: parser XML dengan external entity aktif. **Fix**: matikan DTD/external entity.
- **LFI/RFI & path traversal**: path file dari input (`../`, `include`, `readFile`).
  **Fix**: normalisasi + jangkar direktori dasar, allowlist nama file.

### D. Authentication & Authorization
- **IDOR**: tiap handler yang menerima id objek (`user_id`, `doc_id`, `message_id`,
  `notif_id`, `appointment_id`) harus cek kepemilikan terhadap user login — bukan hanya "sudah login".
  Periksa SEMUA endpoint: chat, notifikasi, dokumen medis, appointment.
- **Horizontal esc.**: client A → data client B; nakes A → data nakes B.
- **Vertical esc.**: client→nakes, nakes→admin, client→admin. Enforcement role di server.
- **JWT**: tolak `alg:none`, cegah HS/RS confusion, secret kuat, wajib `exp`, verifikasi signature.
- **OAuth**: validasi `state`, PKCE, allowlist `redirect_uri`.
- **Reset/session**: token reset acak & kedaluwarsa & sekali pakai; cegah session fixation;
  invalidasi setelah ganti password.
- **Fix**: middleware authz berbasis objek + role di tiap handler; default deny.

### E. Business logic
- Price/quantity tampering (harga dari server, bukan client).
- Race condition pembayaran/kuota/appointment (transaksi/lock/idempotency key).
- Workflow bypass (konsultasi selesai tanpa bayar) — validasi transisi status server.
- Replay endpoint sensitif (nonce/idempotency).

### F. Web security (konfigurasi)
- CORS: jangan reflect `Origin` + `credentials:true`; allowlist.
- CSRF: token anti-CSRF pada aksi state-changing.
- Open redirect: validasi tujuan (allowlist).
- Clickjacking: `frame-ancestors`/`X-Frame-Options`.
- HTML injection di email transaksional: escape data user.
- Tabnabbing: `rel="noopener noreferrer"`.
- Cookie: `Secure`, `HttpOnly`, `SameSite`.

### G. Secrets & data exposure
- Grep `API_KEY`, `SECRET`, `password=`, token, private key di repo/log/pesan error.
- PII pasien/rekam medis di log, response berlebih, storage tak terenkripsi.
- Endpoint debug/admin/swagger terekspos. **Fix**: env/secret manager, rotasi secret bocor,
  matikan debug, minimalkan response, enkripsi at-rest.

### H. AI / LLM (jika ada)
- Prompt injection yang mempengaruhi user lain; kebocoran riwayat lintas user;
  model poisoning via input publik; output yang menipu user lain.
  **Fix**: pisahkan data vs instruksi, isolasi konteks per user.

### I. User enumeration & account oracle
- register/login/forgot-password/resend yang membocorkan eksistensi akun (pesan/status/timing beda).
  **Fix**: respon & waktu seragam, pesan generik.

## Output akhir
1. Ringkasan temuan per severity.
2. Daftar temuan format baku (paling parah dulu).
3. Patch/kode perbaikan tiap temuan.
4. Catatan temuan yang butuh keputusan arsitektur manusia.
