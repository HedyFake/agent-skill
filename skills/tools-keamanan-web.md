---
name: tools-keamanan-web
description: Arsenal tools open-source untuk tiap kategori kerentanan web (A–I), lengkap dengan link GitHub, cara install, contoh perintah non-destruktif, dan template untuk membuat tools sendiri.
version: 1.0
---

# Arsenal Tools Keamanan Web

Referensi tools untuk agent AI saat melakukan audit keamanan. Dipakai bersama
skill code-review dan black-box.

---

## 0.0 KETERSEDIAAN TOOL (penting)

Tool seperti **sqlmap, nmap, nuclei, dalfox** TIDAK dibundel dalam plugin —
mereka harus ada di `$PATH` dan environment butuh akses jaringan keluar.

1. **Cek dulu:** `/bb-tools` → tampil `OK`/`MISS` per tool.
2. **Kalau banyak MISS, pasang:** `/bb-install` (atau `bash scripts/install_tools.sh`).
   - `/bb-install check` — hanya laporkan status, tidak memasang.
   - `/bb-install sqlmap nuclei nmap` — pasang subset tertentu.
   - Installer idempotent, pakai apt/brew/pipx/go/git, dan mencetak baris
     `export PATH=...` yang harus ditambahkan ke `~/.bashrc` lalu buka shell baru.
3. **Kalau tidak bisa install** (sandbox tanpa jaringan / tanpa izin): pakai
   **scanner mandiri** `scripts/scanner_kustom.py` (§10) — stdlib-only, tak perlu
   tool eksternal.

> Pemasangan & pemakaian HANYA untuk target milik sendiri / dalam scope berizin.

---

## 0. RECON & PEMETAAN (jalankan dulu)
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

---

## 1. SCANNER MENYELURUH (DAST all-in-one)
| Tool | Fungsi | GitHub |
|---|---|---|
| **OWASP ZAP** | DAST lengkap, bisa CLI/automation, baseline & full scan | https://github.com/zaproxy/zaproxy |
| **w3af** | Framework audit web (plugin audit/crawl) | https://github.com/andresriancho/w3af |
| **Nuclei** | Template-based scanner (ribuan template CVE/misconfig) | https://github.com/projectdiscovery/nuclei |
| **Nikto** | Scan misconfig & file berisiko server web | https://github.com/sullo/nikto |
| **Wapiti** | Scanner kerentanan web | https://github.com/wapiti-scanner/wapiti |
| Burp Suite | Proxy intercept + scanner (Community/Pro) | https://portswigger.net/burp |

Contoh:
```bash
# ZAP baseline (pasif, aman untuk produksi milik sendiri)
docker run -t zaproxy/zap-stable zap-baseline.py -t https://app-saya.com

nuclei -u https://app-saya.com -severity critical,high
nikto -h https://app-saya.com
w3af_console   # lalu set target & profile audit
```

---

## 2. DIRECTORY / ENDPOINT DISCOVERY (kategori G)
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

---

## 3. INJECTION (kategori A)
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

---

## 4. XSS (kategori B)
| Tool | GitHub |
|---|---|
| **XSStrike** | https://github.com/s0md3v/XSStrike |
| dalfox | https://github.com/hahwul/dalfox |
| kxss | https://github.com/Emoe/kxss |

```bash
python3 xsstrike.py -u "https://app-saya.com/search?q=test"
cat urls.txt | dalfox pipe
```

---

## 5. SERVER-SIDE & FILE (kategori C)
| Jenis | Tool | GitHub |
|---|---|---|
| SSRF | SSRFmap | https://github.com/swisskyrepo/SSRFmap |
| SSRF payload | Gopherus | https://github.com/tarunkant/Gopherus |
| Path traversal | dotdotpwn | https://github.com/wireghoul/dotdotpwn |
| XXE | manual + Burp / payload PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |

```bash
python3 ssrfmap.py -r request.txt -p url -m readfiles
dotdotpwn -m http -h app-saya.com -f /etc/passwd
```

---

## 6. AUTH & AUTHZ (kategori D)
| Jenis | Tool | GitHub |
|---|---|---|
| **JWT** | jwt_tool | https://github.com/ticarpi/jwt_tool |
| IDOR/authz | Autorize (ekstensi Burp) | https://github.com/PortSwigger/autorize |
| Login (hati-hati, berizin) | hydra | https://github.com/vanhauser-thc/thc-hydra |
| Pengujian token | Burp Repeater/Intruder | — |

```bash
# Analisis + uji manipulasi klaim JWT
python3 jwt_tool.py <TOKEN> -T
python3 jwt_tool.py <TOKEN> -X a      # uji alg:none
# IDOR: pakai Autorize — login sbg user A, ulangi request dgn sesi user B, bandingkan
```

---

## 7. BUSINESS LOGIC & RACE CONDITION (kategori E)
| Tool | Fungsi | Sumber |
|---|---|---|
| Turbo Intruder | Kirim banyak request paralel (race) | https://github.com/PortSwigger/turbo-intruder |
| Burp Repeater (group, parallel) | Race condition | — |
| ffuf/custom script | Replay & tampering | lihat §9 |

Mayoritas logika bisnis diuji **manual**: ubah harga/jumlah di request, akses langkah
akhir tanpa bayar, kirim request paralel untuk double-book/saldo ganda.

---

## 8. KONFIGURASI WEB & SECRETS (kategori F & G)
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

---

## 9. SAST — AUDIT KODE SUMBER (untuk skill code-review)
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

---

## 10. SCANNER MANDIRI (tanpa dependensi) — `scripts/scanner_kustom.py`

Kalau `/bb-tools` menunjukkan banyak `MISS` (sqlmap/nuclei/dll. tidak terpasang)
atau environment tidak punya akses jaringan untuk tool eksternal, pakai scanner
bawaan paket ini. **Stdlib-only** (cukup Python 3.8+, tidak perlu `pip install`;
pakai `requests` otomatis bila ada, kalau tidak fallback ke `urllib`).
Semua cek **non-destruktif**: deteksi + bukti minimal, tidak dump data, tidak
mengubah/menghapus, tidak brute force.

### Kategori yang dicakup
| Kategori | CWE | Mode |
|---|---|---|
| Header keamanan & flag cookie | 693/614/1004/1275/1021/319 | pasif (default) |
| CORS misconfig (Origin reflection) | 942 | pasif (default) |
| Reflected XSS (marker + konteks) | 79 | pasif (default) |
| Open redirect | 601 | pasif (default) |
| SQL Injection (error + boolean + time-based) | 89 | `--active` |
| LFI / Path traversal (signature /etc/passwd, read-only) | 22/98 | `--active` |
| IDOR (bandingkan 2 sesi) | 639 | `--cookie-a` + `--cookie-b` |
| User enumeration (respon/status/timing) | 203 | `--enum-url` + user ada/tidak |
| SSRF blind (via listener Anda) | 918 | `--ssrf-callback` |

### Contoh pemakaian
```bash
# Cek pasif cepat (header, CORS, XSS reflektif, open redirect)
python3 scripts/scanner_kustom.py https://app-saya.com --yes-authorized

# Aktifkan deteksi SQLi + LFI pada URL yang punya parameter
python3 scripts/scanner_kustom.py "https://app-saya.com/item?id=1&q=a" \
  --active --yes-authorized

# Sertakan probe SQLi time-based (lebih lambat, 1 probe SLEEP)
python3 scripts/scanner_kustom.py "https://app-saya.com/item?id=1" \
  --active --time-based --yes-authorized

# IDOR: bandingkan resource ber-id dari dua sesi berbeda
python3 scripts/scanner_kustom.py "https://app-saya.com/doc?id=5" \
  --cookie-a "session=AAA" --cookie-b "session=BBB" --yes-authorized

# User enumeration pada endpoint reset/forgot
python3 scripts/scanner_kustom.py https://app-saya.com \
  --enum-url "https://app-saya.com/forgot" \
  --user-ada "ada@mail.com" --user-tdk-ada "nihil-xyz@mail.com" --yes-authorized

# SSRF blind: arahkan parameter ke listener milik Anda, lalu pantau hit
python3 scripts/scanner_kustom.py "https://app-saya.com/fetch?url=x" \
  --ssrf-callback "https://listener-anda.oast.site" --yes-authorized

# Output JSON (untuk pipeline / parsing agent)
python3 scripts/scanner_kustom.py https://app-saya.com --json --yes-authorized
```

### Catatan penting
- **Gate otorisasi**: tanpa `--yes-authorized` scanner menanyakan konfirmasi
  interaktif; di terminal non-interaktif (mis. dijalankan agent) **wajib** pakai
  `--yes-authorized` dan hanya untuk target milik sendiri / dalam scope.
- Semua temuan berstatus **KANDIDAT** — verifikasi & reproduksi manual sebelum
  dilaporkan. SQLi hanya ditandai (error/boolean/time diff), **tidak** di-`--dump`.
- `--rate` (default 0.5s) mengatur jeda antar-request; naikkan untuk target
  produksi / program ketat.
- Scanner ini juga dipanggil otomatis oleh slash command `/audit-url <url>`.

Jika perlu cek yang belum ada, kembangkan `scanner_kustom.py` dengan prinsip
sama: scope aman, non-destruktif, rate-limited, output `[SEVERITY] | lokasi |
CWE | PoC | FIX`.

---

## Alur yang disarankan
1. Recon (§0) → petakan permukaan serang.
2. Scanner menyeluruh (§1) + endpoint discovery (§2) untuk kandidat cepat.
3. Tool spesifik per kategori (§3–§8) untuk membuktikan temuan.
4. SAST (§9) jika ada akses kode.
5. AI verifikasi tiap temuan, buang false positive, susun laporan
   `[SEVERITY] | lokasi | CWE | PoC | FIX`, lalu bantu perbaiki.
