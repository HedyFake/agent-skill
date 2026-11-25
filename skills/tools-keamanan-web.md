---
name: tools-keamanan-web
description: Arsenal tools open-source untuk tiap kategori kerentanan web (A–I), lengkap dengan link GitHub, cara install, contoh perintah non-destruktif, dan template untuk membuat tools sendiri.
version: 1.0
---

# Arsenal Tools Keamanan Web

Referensi tools untuk agent AI saat melakukan audit keamanan. Dipakai bersama
skill code-review dan black-box.

## ATURAN PEMAKAIAN (WAJIB)
1. Jalankan tools HANYA ke target milik pengguna / yang berizin tertulis.
2. Gunakan mode non-destruktif. Hindari: brute force masif, flooding/DoS, payload
   yang menghapus/mengubah data, mass-exploit. PoC = pembuktian minimal.
3. Ganti placeholder `TARGET`, `https://app-saya.com`, `./kode` dengan milik pengguna.
4. Hormati `robots.txt` hanya sebagai info; tetap batasi laju (rate limit) agar tidak
   membebani server produksi.
5. Tools ini berjalan di terminal (idealnya Kali/Parrot/WSL/Docker) — **bukan** di dalam
   ChatGPT. Pola kerja: pengguna/agent menjalankan tool di mesinnya, lalu AI membaca
   output untuk menafsirkan & memverifikasi temuan.

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

## 10. MEMBUAT TOOLS SENDIRI
Jika tool yang ada tidak cocok, AI boleh merancang scanner kecil. Prinsip: input
scope aman, non-destruktif, rate-limited, output terstruktur. Template Python:

```python
#!/usr/bin/env python3
"""Scanner kustom — HANYA untuk target milik sendiri/berizin."""
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
(kirim `Origin` jahat), open redirect, enumerasi user (bandingkan respon/timing).

---

## Alur yang disarankan
1. Recon (§0) → petakan permukaan serang.
2. Scanner menyeluruh (§1) + endpoint discovery (§2) untuk kandidat cepat.
3. Tool spesifik per kategori (§3–§8) untuk membuktikan temuan.
4. SAST (§9) jika ada akses kode.
5. AI verifikasi tiap temuan, buang false positive, susun laporan
   `[SEVERITY] | lokasi | CWE | PoC | FIX`, lalu bantu perbaiki.
