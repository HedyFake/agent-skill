"""Hermes plugin: Auditor Keamanan Web (defensif) + Bug Bounty Workflow berurutan.

Slash commands:
  /audit [codereview|blackbox|tools|workflow]  - panduan
  /audit-sast [path]                           - semgrep SAST
  /audit-url <url> [full]                      - scan URL non-destruktif
  /bb-tools                                    - cek tool yang terpasang
  /bb-install [check|<tool...>]                - pasang arsenal tool (sqlmap/nuclei/dll.)
  /bb-setup <domain>                           - buat workspace + catat otorisasi
  /bb-recon <domain>                           - FASE 2: subdomain + httpx + nmap
  /bb-paths <domain>                           - FASE 3: katana + gau + ffuf
  /bb-inject <url>                             - FASE 4: sqlmap verifikasi (schema saja)
  /bb-xss <url>                                - FASE 5: dalfox
  /bb-tls <domain>                             - FASE 6: testssl + CORScanner
  /bb-sast <path>                              - FASE 8: semgrep + bandit + njsscan
  /bb-all <domain>                             - cetak rencana workflow lengkap


"""
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

PLUGIN_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PLUGIN_DIR / "skills"
SCANNER = PLUGIN_DIR / "scripts" / "scanner_kustom.py"
INSTALLER = PLUGIN_DIR / "scripts" / "install_tools.sh"

_PANDUAN = {
    "codereview": "audit-keamanan-web-codereview.md",
    "blackbox": "audit-keamanan-web-blackbox.md",
    "tools": "tools-keamanan-web.md",
    "workflow": "bugbounty-workflow.md",
}

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253})[a-zA-Z0-9]$")

_TOOLS = (
    "subfinder amass httpx katana gau waybackurls "
    "nmap whatweb ffuf dirsearch gobuster feroxbuster "
    "nuclei nikto sqlmap commix SSTImap dalfox xsstrike "
    "jwt_tool testssl.sh shcheck CORScanner "
    "gitleaks trufflehog semgrep bandit njsscan"
)


def _cari_berkas(nama):
    for base in (SKILLS_DIR, PLUGIN_DIR):
        f = base / nama
        if f.exists():
            return f.read_text(encoding="utf-8")
    return f"(berkas '{nama}' tidak ditemukan di plugin)"


def _domain_valid(d):
    if not d or len(d) > 255:
        return False
    if ".." in d or " " in d or "/" in d or ":" in d:
        return False
    return bool(_DOMAIN_RE.match(d))


def _url_valid(u):
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _workdir(domain):
    # domain sudah divalidasi (hanya [a-zA-Z0-9.-]); aman untuk path.
    return f'"$HOME/bb/{domain}"'


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _cmd_audit(ctx, raw_args):
    arg = (raw_args or "").strip().lower()
    nama = _PANDUAN.get(arg, _PANDUAN["codereview"])
    if arg and arg not in _PANDUAN:
        return ("Pemakaian: /audit [codereview|blackbox|tools|workflow]\n\n"
                + _cari_berkas(_PANDUAN["codereview"]))
    return _cari_berkas(nama)


def _cmd_sast(ctx, raw_args):
    target = (raw_args or ".").strip() or "."
    if target.startswith("-"):
        return "Path tidak boleh diawali '-'. Contoh: /audit-sast ./src"
    return ctx.dispatch_tool(
        "terminal",
        {"command": f"semgrep --config=auto {shlex.quote(target)}"},
    )


def _cmd_url(ctx, raw_args):
    bagian = (raw_args or "").split()
    if not bagian:
        return ("Pemakaian: /audit-url <url> [full]\n"
                "Contoh: /audit-url https://app-milikmu.com\n"
                "PERINGATAN: hanya untuk target milik sendiri / berizin tertulis.")

    url = bagian[0]
    mode = bagian[1].lower() if len(bagian) > 1 else "basic"
    if not _url_valid(url):
        return "URL tidak valid. Harus diawali http:// atau https:// dan punya host."

    q = shlex.quote
    url_q = q(url)

    # FIX: URL TIDAK PERNAH diinterpolasi mentah ke shell. printf menerima URL
    # sebagai argumen yang sudah di-quote — metakarakter netral.
    cmd = (
        "printf '=== Scan non-destruktif untuk %s (pastikan ini milikmu/berizin) ===\\n' "
        + url_q + "; "
        + f"python3 {q(str(SCANNER))} {url_q}"
    )

    if mode == "full":
        cmd += (
            f"; echo '--- testssl (TLS) ---'; "
            f"command -v testssl.sh >/dev/null 2>&1 && testssl.sh --quiet {url_q} "
            f"|| echo 'testssl.sh tidak terpasang, lewati'"
            f"; echo '--- nikto ---'; "
            f"command -v nikto >/dev/null 2>&1 && nikto -h {url_q} -maxtime 120s "
            f"|| echo 'nikto tidak terpasang, lewati'"
            f"; echo '--- nuclei (template deteksi) ---'; "
            f"command -v nuclei >/dev/null 2>&1 && nuclei -u {url_q} -silent "
            f"-severity low,medium,high,critical "
            f"|| echo 'nuclei tidak terpasang, lewati'"
        )
        cmd += ("; echo '--- Catatan: tool injeksi aktif (sqlmap/commix) TIDAK "
                "dijalankan otomatis. Jalankan manual sesuai /audit tools bila perlu. ---'")

    return ctx.dispatch_tool("terminal", {"command": cmd})


# ---------------------------------------------------------------------------
# Bug bounty workflow
# ---------------------------------------------------------------------------

def _cmd_bb_tools(ctx, raw_args):
    cmd = (
        f"for t in {_TOOLS}; do "
        f'command -v "$t" >/dev/null 2>&1 && echo "OK   $t" || echo "MISS $t"; '
        f"done"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_install(ctx, raw_args):
    arg = (raw_args or "").strip().lower()
    q = shlex.quote
    inst = q(str(INSTALLER))
    if arg in ("check", "--check", "cek"):
        cmd = f"bash {inst} --check"
        return ctx.dispatch_tool("terminal", {"command": cmd})
    # subset tool (opsional), divalidasi agar hanya nama tool wajar
    extra = ""
    if arg:
        toks = [t for t in arg.split() if re.fullmatch(r"[a-zA-Z0-9._-]{1,40}", t)]
        extra = " " + " ".join(shlex.quote(t) for t in toks)
    cmd = (
        f"echo '=== install_tools: HANYA di environment yang Anda izinkan ==='; "
        f"if ! command -v bash >/dev/null 2>&1; then echo 'bash tidak ada'; exit 1; fi; "
        f"bash {inst}{extra}"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_setup(ctx, raw_args):
    domain = (raw_args or "").strip().lower()
    if not _domain_valid(domain):
        return ("Domain tidak valid. Contoh: /bb-setup target.com\n"
                "Hanya huruf, angka, titik, dan dash. Tanpa http:// atau path.")

    q = shlex.quote
    cmd = (
        f"WORK={_workdir(domain)}; "
        f'mkdir -p "$WORK"/{{recon,urls,scans,evidence,notes}}; '
        f'cd "$WORK" && pwd; '
        f"printf '[%s] authorized: %s\\n' \"$(date -Is)\" {q(domain)} "
        f'>> notes/log.md; '
        f"cat notes/log.md"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_recon(ctx, raw_args):
    domain = (raw_args or "").strip().lower()
    if not _domain_valid(domain):
        return "Domain tidak valid. Contoh: /bb-recon target.com"

    d = shlex.quote(domain)
    cmd = (
        f"WORK={_workdir(domain)}; "
        f'mkdir -p "$WORK"/{{recon,urls,scans,evidence,notes}}; cd "$WORK"; '
        f"echo '=== FASE 2.1: subdomain enumeration ==='; "
        f"command -v subfinder >/dev/null 2>&1 && subfinder -d {d} -all -silent | tee recon/subs_subfinder.txt || echo 'subfinder MISS, lewati'; "
        f"command -v amass >/dev/null 2>&1 && amass enum -passive -d {d} -o recon/subs_amass.txt 2>/dev/null || true; "
        f"cat recon/subs_*.txt 2>/dev/null | sort -u > recon/subs_all.txt; "
        f"echo \"subdomains: $(wc -l < recon/subs_all.txt)\"; "
        f"echo '=== FASE 2.2: httpx probe ==='; "
        f"if [ -s recon/subs_all.txt ] && command -v httpx >/dev/null 2>&1; then "
        f"httpx -l recon/subs_all.txt -silent -status-code -title -tech-detect -threads 20 -rate-limit 30 | tee recon/live.txt; "
        f"else echo 'httpx MISS atau subs_all kosong, lewati'; fi; "
        f"awk '{{print $1}}' recon/live.txt 2>/dev/null | sort -u > recon/live_hosts.txt; "
        f"echo \"live hosts: $(wc -l < recon/live_hosts.txt 2>/dev/null || echo 0)\"; "
        f"echo '=== FASE 2.3: whatweb ==='; "
        f"if command -v whatweb >/dev/null 2>&1 && [ -s recon/live_hosts.txt ]; then "
        f"while read -r h; do whatweb -q \"$h\" >> recon/tech.txt; sleep 1; done < recon/live_hosts.txt; "
        f"fi; "
        f"echo 'recon selesai — cek recon/live_hosts.txt lalu jalankan /bb-paths'"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_paths(ctx, raw_args):
    domain = (raw_args or "").strip().lower()
    if not _domain_valid(domain):
        return "Domain tidak valid. Contoh: /bb-paths target.com"

    d = shlex.quote(domain)
    cmd = (
        f"WORK={_workdir(domain)}; "
        f'cd "$WORK" 2>/dev/null || {{ echo "workspace belum ada, jalankan /bb-setup dulu"; exit 1; }}; '
        f"echo '=== FASE 3.1: crawling + arsip ==='; "
        f"if [ -s recon/live_hosts.txt ] && command -v katana >/dev/null 2>&1; then "
        f"katana -list recon/live_hosts.txt -d 3 -jc -silent -rl 30 | tee urls/katana.txt; "
        f"else echo 'katana MISS atau live_hosts kosong, lewati'; fi; "
        f"command -v gau >/dev/null 2>&1 && gau {d} | tee urls/gau.txt || true; "
        f"command -v waybackurls >/dev/null 2>&1 && waybackurls {d} | tee urls/wayback.txt || true; "
        f"cat urls/*.txt 2>/dev/null | sort -u > urls/all.txt; "
        f"grep '=' urls/all.txt 2>/dev/null | sort -u > urls/with_params.txt || true; "
        f"echo \"urls total: $(wc -l < urls/all.txt)\"; "
        f"echo \"with params: $(wc -l < urls/with_params.txt 2>/dev/null || echo 0)\"; "
        f"echo '=== FASE 3.2: ffuf directory ==='; "
        f"WL=/usr/share/wordlists/dirb/common.txt; [ -f \"$WL\" ] || WL=./wordlist.txt; "
        f"if [ -f \"$WL\" ] && command -v ffuf >/dev/null 2>&1; then "
        f"ffuf -u \"https://{domain}/FUZZ\" -w \"$WL\" -mc 200,204,301,302,401,403 -rate 40 -t 20 -o scans/ffuf.json -s; "
        f"else echo 'wordlist atau ffuf MISS, lewati'; fi; "
        f"echo 'path discovery selesai — cek urls/with_params.txt lalu /bb-inject atau /bb-xss per URL'"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _host_from_url(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _cmd_bb_inject(ctx, raw_args):
    url = (raw_args or "").strip()
    if not url or not _url_valid(url):
        return ("Pemakaian: /bb-inject <url-dengan-parameter>\n"
                "Contoh: /bb-inject https://target/item?id=1\n"
                "PERINGATAN: hanya verifikasi schema (--dbs), TIDAK dump isi tabel.")
    host = _host_from_url(url)
    if not _domain_valid(host):
        return f"Host tidak valid untuk workspace: {host!r}"

    q = shlex.quote
    url_q = q(url)
    cmd = (
        f"WORK={_workdir(host)}; mkdir -p \"$WORK\"/scans/sqlmap; cd \"$WORK\"; "
        f"if ! command -v sqlmap >/dev/null 2>&1; then echo 'sqlmap MISS, install dulu'; exit 1; fi; "
        f"echo '=== FASE 4.1: sqlmap verifikasi (bukan dump) ==='; "
        f"sqlmap -u {url_q} --batch --level 2 --risk 1 --technique=BEUST --threads=1 --delay=1 --output-dir=scans/sqlmap/ 2>&1 | tee -a scans/sqlmap/run.log; "
        f"echo '--- lanjut cek schema: sqlmap -u URL --batch --dbs ---'"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_xss(ctx, raw_args):
    url = (raw_args or "").strip()
    if not url or not _url_valid(url):
        return ("Pemakaian: /bb-xss <url-dengan-parameter>\n"
                "Contoh: /bb-xss https://target/search?q=test")
    host = _host_from_url(url)
    if not _domain_valid(host):
        return f"Host tidak valid untuk workspace: {host!r}"

    q = shlex.quote
    url_q = q(url)
    cmd = (
        f"WORK={_workdir(host)}; mkdir -p \"$WORK\"/scans; cd \"$WORK\"; "
        f"if ! command -v dalfox >/dev/null 2>&1; then echo 'dalfox MISS, install dulu'; exit 1; fi; "
        f"echo '=== FASE 5: dalfox XSS ==='; "
        f"dalfox url {url_q} --silence --delay 500 | tee -a scans/xss.txt; "
        f"echo 'verifikasi manual di browser dengan akun uji, simpan di evidence/xss-*/'"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_tls(ctx, raw_args):
    domain = (raw_args or "").strip().lower()
    if not _domain_valid(domain):
        return "Domain tidak valid. Contoh: /bb-tls target.com"

    cmd = (
        f"WORK={_workdir(domain)}; "
        f'cd "$WORK" 2>/dev/null || {{ echo "workspace belum ada, jalankan /bb-setup dulu"; exit 1; }}; '
        f"echo '=== FASE 6: TLS + CORS + secrets ==='; "
        f"command -v testssl.sh >/dev/null 2>&1 && testssl.sh --quiet \"https://{domain}\" >> scans/tls.txt 2>&1 || echo 'testssl MISS, lewati'; "
        f"command -v CORScanner >/dev/null 2>&1 && python3 CORScanner.py -u \"https://{domain}\" >> scans/cors.txt 2>&1 || echo 'CORScanner MISS, lewati'; "
        f"command -v gitleaks >/dev/null 2>&1 && gitleaks detect --source . -v 2>/dev/null | tee scans/gitleaks.txt || true; "
        f"echo 'tls/cors/secrets selesai'"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_sast(ctx, raw_args):
    path = (raw_args or ".").strip() or "."
    if path.startswith("-"):
        return "Path tidak boleh diawali '-'. Contoh: /bb-sast ./src"
    q = shlex.quote
    p = q(path)
    cmd = (
        f"mkdir -p scans; "
        f"echo '=== FASE 8: SAST ==='; "
        f"command -v semgrep >/dev/null 2>&1 && semgrep --config=auto {p} | tee scans/semgrep.txt || echo 'semgrep MISS'; "
        f"command -v bandit >/dev/null 2>&1 && bandit -r {p} -f txt 2>/dev/null | tee scans/bandit.txt || true; "
        f"command -v njsscan >/dev/null 2>&1 && njsscan {p} 2>/dev/null | tee scans/njsscan.txt || true"
    )
    return ctx.dispatch_tool("terminal", {"command": cmd})


def _cmd_bb_all(ctx, raw_args):
    domain = (raw_args or "").strip().lower()
    if not _domain_valid(domain):
        return "Domain tidak valid. Contoh: /bb-all target.com"

    return (
        f"PLAN WORKFLOW untuk {domain}\n"
        f"1. /bb-setup {domain}\n"
        f"2. /bb-recon {domain}\n"
        f"3. /bb-paths {domain}\n"
        f"4. /bb-inject <url-dengan-parameter>   (pilih target spesifik dari urls/with_params.txt)\n"
        f"5. /bb-xss <url-dengan-parameter>      (pilih target spesifik)\n"
        f"6. /bb-tls {domain}\n"
        f"7. /bb-sast ./src                      (jika ada akses kode)\n"
        f"\n"
        f"Fase 4-5 dijalankan manual per-URL agar Anda memilih target secara sadar,\n"
        f"dan agar tidak menembak semua endpoint sekaligus. Periksa output tiap fase\n"
        f"sebelum lanjut. Gunakan /bb-tools untuk memastikan tool terpasang."
    )


def register(ctx):
    commands = [
        ("audit", _cmd_audit, "Panduan: /audit [codereview|blackbox|tools|workflow]"),
        ("audit-sast", _cmd_sast, "Semgrep SAST pada path (default: .)"),
        ("audit-url", _cmd_url, "Scan URL non-destruktif: /audit-url <url> [full]"),
        ("bb-tools", _cmd_bb_tools, "Cek tool bug bounty yang terpasang"),
        ("bb-install", _cmd_bb_install, "Pasang arsenal tool (sqlmap/nuclei/dll.): /bb-install [check|<tool...>]"),
        ("bb-setup", _cmd_bb_setup, "Buat workspace: /bb-setup <domain>"),
        ("bb-recon", _cmd_bb_recon, "FASE 2: subdomain + httpx — /bb-recon <domain>"),
        ("bb-paths", _cmd_bb_paths, "FASE 3: katana + gau + ffuf — /bb-paths <domain>"),
        ("bb-inject", _cmd_bb_inject, "FASE 4: sqlmap verifikasi — /bb-inject <url>"),
        ("bb-xss", _cmd_bb_xss, "FASE 5: dalfox XSS — /bb-xss <url>"),
        ("bb-tls", _cmd_bb_tls, "FASE 6: testssl + CORScanner — /bb-tls <domain>"),
        ("bb-sast", _cmd_bb_sast, "FASE 8: semgrep + bandit + njsscan — /bb-sast <path>"),
        ("bb-all", _cmd_bb_all, "Cetak rencana workflow: /bb-all <domain>"),
    ]
    for name, handler, desc in commands:
        ctx.register_command(name, (lambda h: lambda raw: h(ctx, raw))(handler), description=desc)

    try:
        for nama, berkas in (
            ("audit-codereview", _PANDUAN["codereview"]),
            ("audit-blackbox", _PANDUAN["blackbox"]),
            ("bugbounty-workflow", _PANDUAN["workflow"]),
        ):
            path = SKILLS_DIR / berkas
            if path.exists():
                ctx.register_skill(name=nama, path=str(path))
    except Exception:
        pass
