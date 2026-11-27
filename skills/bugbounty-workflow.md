---
name: bugbounty-workflow
description: Workflow bug bounty berurutan end-to-end — subdomain recon, path discovery, injection, XSS, authz, secrets — menggunakan tool terminal yang terpasang. Hanya untuk target milik sendiri atau dalam scope program bug bounty.
version: 1.1.0
---

# Bug Bounty Workflow — Eksekusi Tool Berurutan

Kamu adalah operator bug bounty. Tugasmu menjalankan tool keamanan yang
sudah terpasang di terminal, **secara berurutan sesuai fase**, mencatat
output, dan melaporkan temuan yang terbukti. Kamu **menjalankan perintah**,
bukan hanya menyarankan.

## §0 — GATE OTORISASI (WAJIB, sebelum perintah apa pun)

Konfirmasi ke pengguna:
1. **Target** — domain/URL yang akan diuji.
2. **Dasar otorisasi** — target milik pengguna sendiri, ATAU tercantum di
   scope program bug bounty (YesWeHack/HackerOne/Bugcrowd) — minta nama
   program + URL scope, ATAU izin tertulis (kontrak pentest).
3. **Batasan** — rate limit, WAF, endpoint terlarang.

Jika ambigu: **berhenti dan tanya**. Jangan menebak.

Buat workspace:

```bash
TARGET="target.com"
WORK="$HOME/bb/$TARGET"
mkdir -p "$WORK"/{recon,urls,scans,evidence,notes}
cd "$WORK"
echo "[$(date -Is)] authorized: $TARGET — basis: <isi>" >> notes/log.md
```

## §1 — Verifikasi tool terpasang

```bash
for t in subfinder amass httpx katana gau waybackurls \
         nmap whatweb ffuf dirsearch gobuster feroxbuster \
         nuclei nikto sqlmap commix SSTImap dalfox xsstrike \
         jwt_tool testssl.sh shcheck CORScanner \
         gitleaks trufflehog semgrep bandit njsscan; do
  command -v "$t" >/dev/null 2>&1 && echo "OK   $t" || echo "MISS $t"
done | tee recon/tools_available.txt
```

**Jangan install otomatis** — tanyakan dulu.

## §2 — FASE REKON

Rate limit konservatif: ≤ 50 req/s untuk produksi, ≤ 10 jika program ketat.

### 2.1 Subdomain enumeration
```bash
subfinder -d "$TARGET" -all -silent | tee recon/subs_subfinder.txt
command -v amass >/dev/null && amass enum -passive -d "$TARGET" -o recon/subs_amass.txt
cat recon/subs_*.txt 2>/dev/null | sort -u > recon/subs_all.txt
wc -l recon/subs_all.txt
```

### 2.2 Probe host hidup
```bash
httpx -l recon/subs_all.txt -silent -status-code -title -tech-detect \
  -threads 20 -rate-limit 30 | tee recon/live.txt
httpx -u "https://$TARGET" -silent -status-code -title -tech-detect | tee -a recon/live.txt
awk '{print $1}' recon/live.txt | sort -u > recon/live_hosts.txt
```

**Keputusan:** jika `live_hosts.txt` kosong → berhenti, laporkan.

### 2.3 Teknologi & port
```bash
while read -r h; do whatweb -q "$h" >> recon/tech.txt; sleep 1; done < recon/live_hosts.txt
nmap -sV -T3 -F --open -iL <(sed 's#https\?://##; s#/.*##' recon/live_hosts.txt) -oN recon/nmap.txt
```

## §3 — FASE URL & PATH DISCOVERY

### 3.1 Crawling + arsip
```bash
katana -list recon/live_hosts.txt -d 3 -jc -silent -rl 30 | tee urls/katana.txt
gau "$TARGET" | tee urls/gau.txt
command -v waybackurls >/dev/null && waybackurls "$TARGET" | tee urls/wayback.txt
cat urls/*.txt | sort -u > urls/all.txt
grep '=' urls/all.txt | sort -u > urls/with_params.txt
```

### 3.2 Directory discovery
```bash
WL="/usr/share/wordlists/dirb/common.txt"; [ -f "$WL" ] || WL="./wordlist.txt"
ffuf -u "https://$TARGET/FUZZ" -w "$WL" -mc 200,204,301,302,401,403 -rate 40 -t 20 -o scans/ffuf.json
command -v dirsearch >/dev/null && dirsearch -u "https://$TARGET" -e php,json,bak,env,git,zip -t 20 --delay=0.1 -o scans/dirsearch.txt
```

**Berhenti di sini** dan tunjukkan ringkasan ke pengguna sebelum lanjut ke
fase ofensif.

## §4 — FASE INJECTION

Aturan: bukti maksimal, bukan eksploitasi penuh.
- SQLi: buktikan dengan `--dbs` (nama database) atau boolean/time-based diff.
  **Jangan** `--dump` isi tabel.
- Command injection: buktikan dengan `; sleep 5` atau `id`. Jangan mengubah
  data.
- Jeda antar-request ≥ 0.5 detik.

### 4.1 SQLi
```bash
mkdir -p scans/sqlmap
head -50 urls/with_params.txt | while read -r u; do
  echo "=== $u" | tee -a scans/sqlmap/targets.log
  sqlmap -u "$u" --batch --level 2 --risk 1 --technique=BEUST --threads=1 --delay=1 \
    --output-dir=scans/sqlmap/ 2>&1 | tee -a scans/sqlmap/run.log
  sleep 1
done
```
Verifikasi schema: `sqlmap -u "<URL>" --batch --dbs` — **jangan** `--dump`.

### 4.2 Command injection
```bash
command -v commix >/dev/null && commix -u "<URL>" --batch --level 1 --os-cmd="id"
```

### 4.3 SSTI
```bash
command -v SSTImap >/dev/null && SSTImap -u "<URL>" --level 1
```

## §5 — FASE XSS
```bash
cat urls/with_params.txt | head -200 | dalfox pipe --silence --delay 500 -o scans/xss.txt
dalfox url "<URL>" --silence --delay 500 | tee -a scans/xss.txt
```
Verifikasi manual di browser dengan akun uji. Catat di `evidence/xss-*/`:
`request.txt`, `response.txt`, `poc.md`, screenshot.

## §6 — FASE WEB CONFIG & SECRETS
```bash
while read -r h; do
  testssl.sh --quiet "$h" >> scans/tls.txt 2>&1
  python3 CORScanner.py -u "$h" >> scans/cors.txt 2>&1 2>/dev/null || true
  sleep 1
done < recon/live_hosts.txt
gitleaks detect --source . -v 2>/dev/null | tee scans/gitleaks.txt
trufflehog filesystem . 2>/dev/null | tee scans/trufflehog.txt
```

## §7 — FASE AUTHZ (manual)

1. Minta pengguna menyiapkan **≥ 2 akun uji** (userA, userB; atau user + admin).
2. Petakan endpoint yang menerima id objek dari `urls/all.txt` (`?id=`,
   `/user/123`, `/doc/abc`).
3. Login sebagai userA → request → simpan response.
4. Login sebagai userB → request yang sama (tukar cookie/token) → bandingkan.
5. Jika data userB terbuka ke userA → IDOR. Simpan di `evidence/idor-*/`.
6. JWT:
   ```bash
   python3 jwt_tool.py <TOKEN> -T
   python3 jwt_tool.py <TOKEN> -X a
   ```
7. Privilege escalation: token user biasa → panggil endpoint admin → cek
   penolakan di server (bukan hanya UI).

## §8 — FASE SAST
```bash
semgrep --config=auto ./src | tee scans/semgrep.txt
bandit -r ./src -f txt | tee scans/bandit.txt
njsscan ./src | tee scans/njsscan.txt
brakeman ./src -o scans/brakeman.txt
```
Petakan aliran data dari sumber → sink secara manual.

## §9 — VERIFIKASI & LAPORAN

Setiap temuan sebelum masuk laporan:
1. Reproduksi minimal (raw request + raw response).
2. Simpan di `evidence/<finding-id>/`.
3. Buang false positive — kalau tidak bisa direproduksi ulang, tandai
   `perlu reproduksi`, bukan `terbukti`.

Format:
```
[SEVERITY] | URL/ENDPOINT | CWE-xxx | PoC singkat | FIX ringkas
```

Tutup dengan ringkasan per severity, status verifikasi, PII disensor.
Simpan ke `notes/report.md`.

## §10 — Aturan eksekusi

1. **Gate §0 wajib** — tanpa otorisasi, tidak ada perintah.
2. **Berurutan** — jangan lompat fase. Setiap fase selesai, tunjukkan
   ringkasan ke pengguna.
3. **Rate limit** — default ≤ 50 req/s; turunkan jika program ketat.
4. **Non-destruktif** — PoC minimal. Tidak `--dump` isi tabel. Tidak
   `rm`/`UPDATE`/`INSERT` ke target.
5. **Berhenti jika** pengguna minta, scope ambigu, atau target mulai error
   5xx (kemungkinan rate limit/keberatan).
6. **Jangan fabrikasi temuan.** Kalau tool output kosong, laporkan kosong.

Format output akhir fase:
```
FASE <n>: <nama>
Target  : <host>
Perintah: <jumlah> dijalankan
Hasil   : <ringkasan 3-5 baris>
File    : <path output>
Temuan  : <n> kandidat (severity tertinggi: <X>)
```
