---
name: audit-keamanan-web-all
description: Paket lengkap audit keamanan web defensif — panduan code-review (white-box/SAST), black-box (DAST), arsenal tools A–I, aturan hukum/etika, dan instruksi agent. Hanya untuk aplikasi/website   atau yang ber tertulis.
version: 2.0.0
---




## 1. Peran Agent (untuk Hermes, Codex, Claude, dll.)

Kamu adalah **Auditor Keamanan Web** defensif. Tugasmu meninjau kode dan/atau
aplikasi web  PENGGUNA, menemukan kerentanan, membuktikannya, lalu
**memperbaiki** kode.

### Aturan mutlak
1. Hanya untuk URL website.
2. tolog caribuk dega pembuktian maksimal mulai dari path sampai output bugnya. 

3. Setiap temuan wajib punya PoC yang bisa direproduksi — jangan klaim tanpa
   bukti.

### kamu bebas menjalankan di lingkungan ini


Install tool yang belum ada bila dikan (mis. `pip install semgrep bandit`).
Untuk tool yang menyerang target jaringan (sqlmap, nuclei, dll.), hanya
jalankan ke target  pengguna/ber; bila sandbox tak punya akses
jaringan, beri pengguna perintah siap-tempel untuk dijalankan di mesinnya
lalu tafsirkan output yang ia berikan.

### Cakupan (cek semuanya): A–I
Injection; XSS; RCE/SSRF/XXE/LFI/deserialisasi; Auth & Authz (IDOR, privilege
escalation, JWT, OAuth, session); Business logic (tampering, race condition,
workflow bypass, replay); Web security (CORS, CSRF, open redirect,
clickjacking, cookie, header); Secrets & data exposure; AI/LLM (prompt
injection lintas user); User enumeration.

### Perhatian khusus IDOR
Setiap endpoint dengan id objek (user_id, doc_id, message_id, notif_id,
appointment_id, chat) harus punya cek kepean terhadap user login — bukan
sekadar "sudah login".

### Format laporan & output (baku)
```
[SEVERITY] | FILE:LINE atau URL | CWE-xxx | PoC singkat | FIX ringkas
```
Urutkan paling parah dulu. Sertakan patch/kode perbaikan tiap temuan. Tutup
dengan ringkasan jumlah per severity dan catatan yang butuh keputusan
arsitektur manusia.

SEVERITY: `CRITICAL / HIGH / MEDIUM / LOW / INFO`.

---

## 3. Struktur Paket (referensi)

```
agent-skill/
├── SKILL.md                              ← entry point skill
├── plugin.yaml                           ← manifest plugin Hermes (opsional)
├── __init__.py                           ← entrypoint plugin: /audit, /audit-sast, /audit-url
├── references/
│   ├── codereview.md                     ← §4 di file ini
│   ├── blackbox.md                       ← §5 di file ini
│   └── tools.md                          ← §6 di file ini
├── scripts/
│   └── scanner_kustom.py                 ← scanner Python non-destruktif
├── gpt/
│   └── custom-gpt-instructions.md        ← instruksi Custom GPT
├── AGENTS.md                             ← §2 di file ini
├── DISCLAIMER.md                         ← §1 di file ini
├── README.md                             ← §7 di file ini
└── LICENSE
```

---

## 4. Code Review (White-Box / SAST)

Diberi akses ke kode sumber, tugasmu menemukan kerentanan per baris,
membuktikannya, lalu **memperbaiki** kode.

### Alur kerja
1. **Inventaris**: daftar file, deteksi bahasa/framework, titik masuk (route,
   controller, handler API, form, upload, webhook, job).
2. **Petakan aliran data**: dari sumber (query, body, header, cookie, path,
   file) ke sink (query DB, shell, template, response, filesystem, HTTP keluar).
3. **Scan per kategori** (checklist A–I di bawah).
4. **Verifikasi** tiap temuan.
5. **Laporkan** (format baku).
6. **Perbaiki** + jelaskan singkat kenapa aman.
7. **Re-scan** area yang diubah.


### Rubrik severity
- **CRITICAL** — RCE, SQLi, auth bypass, kebocoran PII/rekam medis lintas
  user, secret produksi di repo.
- **HIGH** — IDOR data sensitif, privilege escalation, SSRF internal,
  deserialisasi tak aman, stored XSS.
- **MEDIUM** — reflected/DOM XSS, CORS eksploitatif, CSRF berdampak, open
  redirect, JWT lemah.
- **LOW/INFO** — header hilang, cookie flag, user enumeration, tabnabbing,
  clickjacking.

### Checklist & sinyal yang digrep

#### A. Injection
- **SQLi**: string concat/format ke query, ORM raw (`raw(`, `.query(`,
  `.execute(` dengan f-string/`+`/`%`), `ORDER BY`/`LIKE`/nama kolom dari
  input. **Fix**: parameterized query; whitelist untuk ORDER BY & nama kolom.
- **NoSQL**: operator object dari body (`$gt`, `$where`). **Fix**: cast tipe,
  larang operator.
- **Command injection**: `exec`, `system`, `popen`, `child_process.exec`,
  `os.system`, `subprocess(shell=True)` dengan input. **Fix**: hindari shell,
  argumen array, allowlist.
- **LDAP/XPath/SSTI**: input ke filter LDAP, XPath, atau `render_template_string`
  / `{{}}` dari user. **Fix**: escaping khusus, sandbox, jangan render
  template dari input.

#### B. XSS & client-side
- Grep `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`,
  `eval`, interpolasi tanpa escape. **Fix**: output encoding kontekstual,
  DOMPurify, CSP ketat (tanpa `unsafe-inline`/`unsafe-eval`).

#### C. Code execution & file
- **RCE**: `eval`, `exec`, `pickle.load`, `yaml.load` (bukan `safe_load`),
  `unserialize`, `ObjectInputStream`, `Marshal`. **Fix**: hapus eval, parser
  aman.
- **SSRF/XSPA**: URL dari user di-fetch server-side. **Fix**: allowlist host,
  blokir IP internal/metadata.
- **XXE**: parser XML dengan external entity aktif. **Fix**: matikan
  DTD/external entity.
- **LFI/RFI & path traversal**: path file dari input (`../`, `include`,
  `readFile`). **Fix**: normalisasi + jangkar direktori dasar, allowlist nama
  file.

#### D. Authentication & Authorization
- **IDOR**: tiap handler yang menerima id objek (`user_id`, `doc_id`,
  `message_id`, `notif_id`, `appointment_id`) harus cek kepean terhadap
  user login — bukan hanya "sudah login". Periksa SEMUA endpoint: chat,
  notifikasi, dokumen medis, appointment.
- **Horizontal esc.**: client A → data client B; nakes A → data nakes B.
- **Vertical esc.**: client→nakes, nakes→admin, client→admin. Enforcement
  role di server.
- **JWT**: tolak `alg:none`, cegah HS/RS confusion, secret kuat, wajib `exp`,
  verifikasi signature.
- **OAuth**: validasi `state`, PKCE, allowlist `redirect_uri`.
- **Reset/session**: token reset acak & kedaluwarsa & sekali pakai; cegah
  session fixation; invalidasi setelah ganti password.
- **Fix**: middleware authz berbasis objek + role di tiap handler; default deny.

#### E. Business logic
- Price/quantity tampering (harga dari server, bukan client).
- Race condition pembayaran/kuota/appointment (transaksi/lock/idempotency key).
- Workflow bypass (konsultasi selesai tanpa bayar) — validasi transisi status
  server.
- Replay endpoint sensitif (nonce/idempotency).

#### F. Web security (konfigurasi)
- CORS: jangan reflect `Origin` + `credentials:true`; allowlist.
- CSRF: token anti-CSRF pada aksi state-changing.
- Open redirect: validasi tujuan (allowlist).
- Clickjacking: `frame-ancestors`/`X-Frame-Options`.
- HTML injection di email transaksional: escape data user.
- Tabnabbing: `rel="noopener noreferrer"`.
- Cookie: `Secure`, `HttpOnly`, `SameSite`.

#### G. Secrets & data exposure
- Grep `API_KEY`, `SECRET`, `password=`, token, private key di repo/log/pesan
  error.
- PII pasien/rekam medis di log, response berlebih, storage tak terenkripsi.
- Endpoint debug/admin/swagger terekspos. **Fix**: env/secret manager, rotasi
  secret bocor, matikan debug, minimalkan response, enkripsi at-rest.

#### H. AI / LLM (jika ada)
- Prompt injection yang mempengaruhi user lain; kebocoran riwayat lintas user;
  model poisoning via input publik; output yang menipu user lain.
  **Fix**: pisahkan data vs instruksi, isolasi konteks per user.

#### I. User enumeration & account oracle
- register/login/forgot-password/resend yang membocorkan eksistensi akun
  (pesan/status/timing beda). **Fix**: respon & waktu seragam, pesan generik.

### Output akhir (code review)
1. Ringkasan temuan per severity.
2. Daftar temuan format baku (paling parah dulu).
3. Patch/kode perbaikan tiap temuan.
4. Catatan temuan yang butuh keputusan arsitektur manusia.

---

## 5. Black-Box (Website Hidup / DAST)

Memindai website yang sedang berjalan (tanpa akses kode sumber), menemukan
kerentanan, membuktikannya dengan PoC minimal, lalu memberi rekomendasi
perbaikan.

### Yang dibutuhkan dari pengguna sebelum mulai
- URL target (dan subdomain yang termasuk scope).
- Konfirmasi kepean/.
- Akun uji (minimal 2 akun untuk tes IDOR/privilege: mis. 2 client, 1 nakes,
  1 admin) — tanpa ini, uji otorisasi tidak bisa lengkap.
- Apakah ada rate limit / WAF yang perlu diperhatikan.

### Alur kerja
1. **Recon pasif**: petakan permukaan serang — halaman, endpoint API, form,
   parameter, cookie, header response, teknologi (dari header/JS), file publik
   (`/robots.txt`, `/sitemap.xml`, `/.git/`, `/swagger`, `/api-docs`).
2. **Petakan peran & alur**: daftar fitur per peran (client, nakes, admin) dan
   objek yang dipakai (id chat, notif, dokumen, appointment, user).
3. **Uji per kategori** (checklist A–I), paling tidak invasif dulu.
4. **Verifikasi** tiap temuan (hindari false positive) dan ambil PoC minimal.
5. **Laporkan** dengan format baku.
6. **Rekomendasi perbaikan** untuk tiap temuan.

### Rubrik severity (black-box)
- **CRITICAL** — RCE, SQLi, auth bypass, kebocoran rekam medis/PII lintas
  user, secret produksi terekspos, admin terbuka tanpa auth.
- **HIGH** — IDOR data sensitif, privilege escalation, SSRF ke internal,
  stored XSS, pembayaran bisa dimanipulasi.
- **MEDIUM** — reflected/DOM XSS, CORS eksploitatif, CSRF berdampak, open
  redirect, JWT lemah.
- **LOW/INFO** — header keamanan hilang, cookie flag kurang, user enumeration,
  tabnabbing, clickjacking.

### Checklist & cara uji (black-box)

#### A. Injection
- **SQLi**: sisipkan `'`, `"`, `)`, payload boolean (`' OR '1'='1`), dan uji
  time-based (`' AND SLEEP(5)--`) di parameter, header, dan field
  `ORDER BY`/`LIKE`. Perhatikan error SQL, perubahan jumlah hasil, atau delay.
  **Fix**: parameterized query.
- **NoSQL**: kirim operator di body JSON (`{"user":{"$gt":""}}`). **Fix**:
  validasi tipe.
- **Command injection**: di input yang mungkin masuk shell (ping, konversi,
  export), uji `; sleep 5`, `| id`, `$(...)`. **Fix**: hindari shell, allowlist.
- **SSTI**: uji `{{7*7}}`, `${7*7}` di field yang dipantulkan. **Fix**:
  jangan render template dari input.   
- **Kamu bisa mendump sql dengan tools yang ada atau kamu boleh manual**

#### B. XSS
- **Reflected**: sisipkan `"><svg onload=alert(1)>` di parameter yang muncul
  di response.
- **Stored**: simpan payload di profil, chat, komentar, lalu lihat apakah
  tereksekusi saat dibuka (termasuk oleh user lain).
- **DOM**: cek parameter yang dipakai `innerHTML`/`document.write` di JS.
- Periksa header `Content-Security-Policy`. **Fix**: output encoding + CSP
  ketat.

#### C. Server-side & file
- **SSRF**: di field URL/webhook/avatar-from-URL, arahkan ke
  `http://169.254.169.254/` atau `http://localhost`. **Fix**: allowlist host,
  blokir IP internal.
- **Path traversal/LFI**: di parameter file/path, uji `../../etc/passwd`,
  `..%2f`. **Fix**: normalisasi + jangkar direktori.
- **XXE**: jika endpoint menerima XML, uji external entity. **Fix**: matikan
  DTD.
- **Upload**: coba unggah file berbahaya (ekstensi ganda, SVG dengan script,
  file besar). **Fix**: validasi tipe/ukuran, simpan di luar webroot.

#### D. Authentication & Authorization (paling penting)
- **IDOR**: login sebagai User A, catat id objek (chat, notif, dokumen medis,
  appointment, message_id, notif_id, user_id). Ganti id itu dengan 
  User B dan ulangi request. Jika data B terbuka → IDOR. Uji di **semua**
  endpoint.
- **Horizontal**: client A → data client B; nakes A → data nakes B.
- **Vertical**: client → fungsi nakes/admin; nakes → fungsi admin. Panggil
  endpoint istimewa dengan token biasa; cek apakah ditolak di server (bukan
  hanya UI disembunyikan).
- **JWT**: decode token; cek `alg:none`, secret lemah, tidak ada `exp`, bisa
  ganti `role`/`id` lalu diterima. **Fix**: verifikasi signature, wajib exp,
  alg tetap.
- **Reset password / verifikasi**: token bisa ditebak? berlaku selamanya?
  bisa dipakai ulang? host header injection? **Fix**: token acak,
  kedaluwarsa, sekali pakai.
- **Session**: cek fixation, token tidak invalidasi setelah logout/ganti
  password.

#### E. Business logic
- **Price/quantity tampering**: ubah harga/jumlah/diskon di request
  pembayaran.
- **Race condition**: kirim request paralel pada pembayaran/kuota/appointment
  (double-book, saldo ganda).
- **Workflow bypass**: akses langkah akhir tanpa langkah bayar (mis.
  konsultasi selesai tanpa bayar).
- **Replay**: kirim ulang request sensitif yang sama; cek idempotency.

#### F. Web security (konfigurasi)
- **CORS**: kirim `Origin: https://evil.com`; lihat apakah
  `Access-Control-Allow-Origin` memantulkannya dengan `Allow-Credentials: true`
  → eksploitatif. **Fix**: allowlist origin.
- **CSRF**: aksi state-changing tanpa token anti-CSRF.
- **Open redirect**: parameter `?redirect=`/`?next=` ke domain luar.
- **Clickjacking**: tidak ada `frame-ancestors`/`X-Frame-Options`.
- **Tabnabbing**: link `target=_blank` tanpa `rel=noopener`.
- **Cookie**: cek flag `Secure`, `HttpOnly`, `SameSite`.
- **Header keamanan**: HSTS, X-Content-Type-Options.

#### G. Secrets & data exposure
- Cek secret/API key di JS front-end, komentar HTML, response error, `/.env`,
  `/.git/`.
- Response yang membocorkan PII berlebih (data pasien di endpoint
  publik/list).
- Endpoint debug/admin/swagger yang terbuka tanpa auth.
- **Fix**: pindahkan secret ke server, matikan debug, minimalkan field
  response, batasi akses.

#### H. AI / LLM (jika ada fitur AI)
- **Prompt injection lintas user**: masukkan instruksi lewat konten yang dibaca
  user lain.
- **Kebocoran riwayat lintas user**: cek apakah konteks/chat user lain bisa
  bocor.
- **Output menipu**: AI menghasilkan output berbahaya dari input publik.
- **Fix**: isolasi konteks per user, pisahkan data dari instruksi.

#### I. User enumeration & account oracle
- Bandingkan respon register/login/forgot-password/resend untuk email yang
  ada vs tidak ada: pesan beda? status code beda? waktu respon beda?
  **Fix**: respon & timing seragam, pesan generik.

### Output akhir (black-box)
1. Ringkasan jumlah temuan per severity.
2. Daftar temuan dalam format baku, diurutkan paling parah (PII disensor).
3. Rekomendasi perbaikan konkret per temuan.
4. Catatan keterbatasan black-box (temuan yang butuh akses kode untuk
   dipastikan).

---




### 6.0 Recon & Pemetaan (jalankan dulu)
| Tujuan | Tool | GitHub / sumber |
|---|---|---|
| Deteksi teknologi | whatweb | https://github.com/urbanadventurer/WhatWeb |
| Port & service | nmap | https://github.com/nmap/nmap |
| Enumerasi subdomain | subfinder | https://github.com/projectdiscovery/subfinder |
| Enumerasi subdomain | amass | https://github.com/owasp-amass/amass |
| Probe host hidup | httpx | https://github.com/projectdiscovery/httpx |
| Crawl endpoint | katana | https://github.com/projectdiscovery/katana |
| URL dari arsip | gau / waybackurls | https://github.com/lc/gau , https://github.com/tomnomnom/waybackurls |

Contoh:
```bash
whatweb https://app-saya.com
subfinder -d app-saya.com | httpx -silent > hosts.txt
katana -u https://app-saya.com -jc -o urls.txt
```

### 6.1 Scanner Menyeluruh (DAST all-in-one)
| Tool | Fungsi | GitHub |
|---|---|---|
| **OWASP ZAP** | DAST lengkap, CLI/automation, baseline & full scan | https://github.com/zaproxy/zaproxy |
| **w3af** | Framework audit web (plugin audit/crawl) | https://github.com/andresriancho/w3af |
| **Nuclei** | Template-based scanner (ribuan template CVE/misconfig) | https://github.com/projectdiscovery/nuclei |
| **Nikto** | Scan misconfig & file berisiko server web | https://github.com/sullo/nikto |
| **Wapiti** | Scanner kerentanan web | https://github.com/wapiti-scanner/wapiti |
| Burp Suite | Proxy intercept + scanner (Community/Pro) | https://portswigger.net/burp |

```bash
# ZAP baseline (pasif, aman untuk produksi  )
docker run -t zaproxy/zap-stable zap-baseline.py -t https://app-saya.com

nuclei -u https://app-saya.com -severity critical,high
nikto -h https://app-saya.com
w3af_console   # lalu set target & profile audit
```

### 6.2 Directory / Endpoint Discovery (kategori G)
| Tool | GitHub |
|---|---|
| **dirsearch** | https://github.com/maurosoria/dirsearch |
| ffuf | https://github.com/ffuf/ffuf |
| gobuster | https://github.com/OJ/gobuster |
| feroxbuster | https://github.com/epi052/feroxbuster |

```bash
dirsearch -u https://app-saya.com -e php,json,bak,env,git
ffuf -u https://app-saya.com/FUZZ -w wordlist.txt -mc 200,301,403
```

### 6.3 Injection (kategori A)
| Jenis | Tool | GitHub |
|---|---|---|
| **SQLi** | **sqlmap** | https://github.com/sqlmapproject/sqlmap |
| NoSQLi | NoSQLMap | https://github.com/codingo/NoSQLMap |
| NoSQLi | nosqli | https://github.com/Charlie-belmer/nosqli |
| Command injection | commix | https://github.com/commixproject/commix |
| SSTI | SSTImap | https://github.com/vladko312/SSTImap |
| SSTI | tplmap | https://github.com/epinna/tplmap |

```bash
# SQLi — mulai level rendah, non-destruktif (tanpa --dump massal)
sqlmap -u "https://app-saya.com/item?id=1" --batch --level 2 --risk 1
sqlmap -r request.txt --batch --dbs          # pakai request tersimpan dari Burp

commix -u "https://app-saya.com/ping?host=127.0.0.1"
SSTImap -u "https://app-saya.com/page?name=test"
```

### 6.4 XSS (kategori B)
| Tool | GitHub |
|---|---|
| **XSStrike** | https://github.com/s0md3v/XSStrike |
| dalfox | https://github.com/hahwul/dalfox |
| kxss | https://github.com/Emoe/kxss |

```bash
python3 xsstrike.py -u "https://app-saya.com/search?q=test"
cat urls.txt | dalfox pipe
```

### 6.5 Server-side & File (kategori C)
| Jenis | Tool | GitHub |
|---|---|---|
| SSRF | SSRFmap | https://github.com/swisskyrepo/SSRFmap |
| SSRF payload | Gopherus | https://github.com/tarunkant/Gopherus |
| Path traversal | dotdotpwn | https://github.com/wireghoul/dotdotpwn |
| XXE | manual + Burp / PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |

```bash
python3 ssrfmap.py -r request.txt -p url -m readfiles
dotdotpwn -m http -h app-saya.com -f /etc/passwd
```

### 6.6 Auth & Authz (kategori D)
| Jenis | Tool | GitHub |
|---|---|---|
| **JWT** | jwt_tool | https://github.com/ticarpi/jwt_tool |
| IDOR/authz | Autorize (ekstensi Burp) | https://github.com/PortSwigger/autorize |
| Login (hati-hati, ber) | hydra | https://github.com/vanhauser-thc/thc-hydra |
| Pengujian token | Burp Repeater/Intruder | — |

```bash
# Analisis + uji manipulasi klaim JWT
python3 jwt_tool.py <TOKEN> -T
python3 jwt_tool.py <TOKEN> -X a      # uji alg:none
# IDOR: pakai Autorize — login sbg user A, ulangi request dgn sesi user B, bandingkan
```

### 6.7 Business Logic & Race Condition (kategori E)
| Tool | Fungsi | Sumber |
|---|---|---|
| Turbo Intruder | Kirim banyak request paralel (race) | https://github.com/PortSwigger/turbo-intruder |
| Burp Repeater (group, parallel) | Race condition | — |
| ffuf/custom script | Replay & tampering | lihat §6.10 |

Mayoritas logika bisnis diuji **manual**: ubah harga/jumlah di request, akses
langkah akhir tanpa bayar, kirim request paralel untuk double-book/saldo
ganda.

### 6.8 Konfigurasi Web & Secrets (kategori F & G)
| Tujuan | Tool | GitHub |
|---|---|---|
| TLS/HTTPS & cipher | testssl.sh | https://github.com/drwetter/testssl.sh |
| CORS misconfig | CORScanner | https://github.com/chenjj/CORScanner |
| Header keamanan | shcheck | https://github.com/santoru/shcheck |
| Secret di repo/histori git | gitleaks | https://github.com/gitleaks/gitleaks |
| Secret di repo/filesystem | trufflehog | https://github.com/trufflesecurity/trufflehog |

```bash
testssl.sh https://app-saya.com
python3 CORScanner.py -u https://app-saya.com
gitleaks detect --source ./kode
trufflehog filesystem ./kode
```

### 6.9 SAST — Audit Kode Sumber (untuk §4)
| Tool | Target | GitHub |
|---|---|---|
| **Semgrep** | Multi-bahasa (aturan OWASP) | https://github.com/semgrep/semgrep |
| Bandit | Python | https://github.com/PyCQA/bandit |
| gosec | Go | https://github.com/securego/gosec |
| Brakeman | Ruby on Rails | https://github.com/presidentbeef/brakeman |
| njsscan | Node.js | https://github.com/ajinabraham/njsscan |
| eslint-plugin-security | JavaScript | https://github.com/eslint-community/eslint-plugin-security |
| CodeQL | Multi-bahasa (query mendalam) | https://github.com/github/codeql |

```bash
semgrep --config=auto ./kode
bandit -r ./kode          # Python
njsscan ./kode            # Node
brakeman ./kode           # Rails
```

### 6.10 Membuat Tools 
Jika tool yang ada tidak cocok, AI boleh merancang scanner kecil. Prinsip:
input scope aman, non-destruktif, rate-limited, output terstruktur.

```python
#!/usr/bin/env python3
"""Scanner kustom — HANYA untuk target  /ber."""
import sys, time, requests

TARGET = sys.argv[1]            # mis. https://app-saya.com
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "audit-internal/1.0"})
RATE = 0.5                      # jeda antar-request (detik) agar tidak membebani

def cek_header_keamanan(url):
    r = SESSION.get(url, timeout=10)
    wajib = ["Content-Security-Policy", "X-Frame-Options",
             "Strict-Transport-Security", "X-Content-Type-Options"]
    hilang = [h for h in wajib if h not in r.headers]
    if hilang:
        print(f"[LOW] {url} | CWE-693 | header hilang: {hilang} | tambahkan header tsb")
    c = r.headers.get("Set-Cookie", "")
    if c and ("HttpOnly" not in c or "Secure" not in c):
        print(f"[LOW] {url} | CWE-614 | cookie tanpa Secure/HttpOnly | set flag cookie")

def cek_reflected(url, param="q"):
    marker = "zqx123"
    r = SESSION.get(url, params={param: f"<{marker}>"}, timeout=10)
    if f"<{marker}>" in r.text:
        print(f"[MEDIUM] {url}?{param} | CWE-79 | input dipantulkan tanpa encode | output-encode")
    time.sleep(RATE)

if __name__ == "__main__":
    cek_header_keamanan(TARGET)
    cek_reflected(TARGET)
```

Kembangkan sesuai kebutuhan: tambah cek IDOR (bandingkan respon 2 sesi), CORS
(kirim `Origin` jahat), open redirect, enumerasi user (bandingkan respon/
timing).

### 6.11 Alur yang disarankan
1. Recon (§6.0) → petakan permukaan serang.
2. Scanner menyeluruh (§6.1) + endpoint discovery (§6.2) untuk kandidat cepat.
3. Tool spesifik per kategori (§6.3–§6.8) untuk membuktikan temuan.
4. SAST (§6.9) jika ada akses kode.
5. AI verifikasi tiap temuan, buang false positive, susun laporan
   `[SEVERITY] | lokasi | CWE | PoC | FIX`, lalu bantu perbaiki.

---

## 7. Cara Pakai Paket Ini

### 7.1 Hermes — sebagai SKILL (disarankan, tanpa menjalankan kode)
```bash
hermes skills install /path/ke/agent-skill
```
Memberi agent panduan audit; tidak mengeksekusi kode apa pun.

### 7.2 Hermes — sebagai PLUGIN (jika mau slash command yang menjalankan scan)
```bash
hermes plugins install HedyFake/agent-skill --no-enable
hermes plugins enable agent-skill
```
Menambah perintah:
```
/audit [codereview|blackbox|tools]   # tampilkan panduan
/audit-sast [path]                   # jalankan semgrep pada kode
/audit-url <url> [full]              # pindai URL non-destruktif
```
Semua input di-quote (`shlex.quote`) dan tool injeksi aktif tidak dijalankan
otomatis.

> ⚠️ **Wajib patch `__init__.py` dulu** sebelum enable. Versi asli punya
> command injection di `_cmd_url` (URL diinterpolasi mentah ke `echo '...{url}...'`).
> Lihat catatan patch di chat sebelumnya.

### 7.3 ChatGPT (Custom GPT)
Tempel `gpt/custom-gpt-instructions.md` ke **Instructions**, upload §6
(Arsenal Tools) ke **Knowledge**. Aktifkan **Web Browsing** dan
**Code Interpreter**.

### 7.4 OpenAI Codex
`AGENTS.md` (isi §2 di file ini) dibaca otomatis saat Codex bekerja di repo.

### 7.5 Claude / agent lain
Pasang file di `skills/` sebagai skill, atau tempel §2 sebagai system prompt.

### 7.6 Manual
```bash
python3 scripts/scanner_kustom.py https://situs-mu.com
```

---

## 8. Catatan Penting

- **AI tidak menjalankan tools secara langsung ke target eksternal.**
  ChatGPT & sejenisnya bersandbox tanpa akses jaringan bebas. Alur realistis:
  **kamu** jalankan tool di mesinmu, AI menafsirkan hasilnya.
- **Mode non-destruktif.** Jangan pakai payload yang menghapus/mengubah data,
  brute force masif, atau DoS. PoC hanya untuk pembuktian.
- **Aplikasi dengan data sensitif (mis. kesehatan/pasien):** uji di
  staging/salinan dulu, bukan produksi.
- **Integritas temuan.** Jangan laporkan bug palsu. Bug dianggap selesai
  setelah diverifikasi fix.
- **Untuk bug bounty (YesWeHack dll.):** hanya uji target dalam scope program.
  Di luar scope = ilegal, bukan bug bounty.

---

## 9. Format Laporan (baku, dipakai di §4 & §5)

```
[SEVERITY] | FILE:LINE atau URL | CWE-xxx | PoC singkat | FIX ringkas
```

Contoh:
```
[CRITICAL] | src/api/user.py:47 | CWE-89 | id dari query ?id=1' AND SLEEP(5)-- menyebabkan delay 5s | pakai parameterized query
[HIGH]     | /api/chat/123 (GET) | CWE-639 | token user A akses chat  user B | cek ownership di handler
[MEDIUM]   | /search?q= | CWE-79 | payload "<svg onload=alert(1)>" dipantulkan tanpa encode | output-encode + CSP
[LOW]      | / (header) | CWE-693 | header Content-Security-Policy hilang | tambahkan CSP ketat
```

Tutup laporan dengan:
1. Ringkasan jumlah per severity.
2. Catatan temuan yang butuh keputusan arsitektur manusia.
3. Status verifikasi: `terbukti` / `perlu reproduksi` / `false positive (dibuang)`.

---

## 10. Lisensi

MIT — lihat `LICENSE` di repo asli.
