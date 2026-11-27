#!/usr/bin/env python3
"""
scanner_kustom.py — scanner kerentanan web ringan, NON-DESTRUKTIF, stdlib-only.

HANYA untuk target milik sendiri atau yang tercantum dalam scope program
bug bounty / izin tertulis. Scanner ini MENDETEKSI & MEMBUKTIKAN secara
minimal, BUKAN mengeksploitasi: tidak dump data, tidak mengubah/menghapus,
tidak brute force, tidak DoS.

Tidak butuh dependensi eksternal — cukup Python 3.8+ (pakai urllib stdlib).
Kalau modul `requests` ada, dipakai; kalau tidak, fallback ke urllib.

Kategori yang dicakup:
  Pasif/aman (jalan default, 1 request benign per cek):
    - Header keamanan & flag cookie            (CWE-693/614/1004/1275/1021/319)
    - CORS misconfig (Origin reflection)       (CWE-942)
    - Reflected XSS (marker, deteksi konteks)  (CWE-79)
    - Open redirect                            (CWE-601)
  Aktif (butuh flag --active, tetap non-destruktif / read-only):
    - SQL Injection: error-based + boolean-based + time-based (deteksi)  (CWE-89)
    - LFI / Path traversal: signature /etc/passwd (read-only)   (CWE-22/98)
  Butuh input tambahan:
    - IDOR            : --cookie-a + --cookie-b (bandingkan 2 sesi)  (CWE-639)
    - User enumeration: --enum-url + --user-ada + --user-tdk-ada    (CWE-203)
    - SSRF (blind)    : --ssrf-callback <url-listener-anda>         (CWE-918)

Contoh:
  python3 scanner_kustom.py https://app-saya.com
  python3 scanner_kustom.py "https://app-saya.com/item?id=1&q=a" --active
  python3 scanner_kustom.py "https://app-saya.com/doc?id=5" \
      --cookie-a "session=AAA" --cookie-b "session=BBB"
  python3 scanner_kustom.py https://app-saya.com --json
"""
import argparse
import json
import re
import sys
import time
import difflib
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

# ---------------------------------------------------------------------------
# Lapisan HTTP (requests bila ada, kalau tidak urllib stdlib)
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except Exception:
    _HAVE_REQUESTS = False
    import urllib.request
    import urllib.error

UA = "audit-internal/2.0 (authorized-scan-only)"


class Resp:
    """Respon ternormalisasi: .status, .headers (case-insensitive), .text, .elapsed"""
    def __init__(self, status, headers, text, elapsed):
        self.status = status
        self._headers = {k.lower(): v for k, v in headers.items()}
        self.text = text or ""
        self.elapsed = elapsed

    def header(self, name, default=""):
        return self._headers.get(name.lower(), default)

    @property
    def length(self):
        return len(self.text)


def http_get(url, headers=None, cookie=None, timeout=12, allow_redirects=True):
    """GET tunggal, non-destruktif. Mengembalikan Resp atau melempar RuntimeError."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    if cookie:
        hdrs["Cookie"] = cookie

    t0 = time.time()
    if _HAVE_REQUESTS:
        try:
            r = requests.get(url, headers=hdrs, timeout=timeout,
                             allow_redirects=allow_redirects)
        except requests.RequestException as e:
            raise RuntimeError(str(e))
        return Resp(r.status_code, dict(r.headers), r.text, time.time() - t0)

    # fallback urllib
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(
        *( [_NoRedirect()] if not allow_redirects else [] )
    )
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1_000_000).decode("utf-8", "replace")
            return Resp(resp.status, dict(resp.headers), body, time.time() - t0)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(1_000_000).decode("utf-8", "replace")
        except Exception:
            pass
        return Resp(e.code, dict(e.headers or {}), body, time.time() - t0)
    except Exception as e:
        raise RuntimeError(str(e))


# ---------------------------------------------------------------------------
# Util
# ---------------------------------------------------------------------------

def params_of(url):
    """Ambil daftar nama parameter query dari URL."""
    q = urlparse(url).query
    return [k for k, _ in parse_qsl(q, keep_blank_values=True)]


def with_param(url, name, value):
    """Kembalikan URL dengan satu parameter query di-set ke value (param lain tetap)."""
    parts = list(urlparse(url))
    q = dict(parse_qsl(parts[4], keep_blank_values=True))
    q[name] = value
    parts[4] = urlencode(q)
    return urlunparse(parts)


def similarity(a, b):
    """Rasio kemiripan 0..1 dua body (dipotong agar cepat)."""
    a, b = a[:20000], b[:20000]
    return difflib.SequenceMatcher(None, a, b).ratio()


def finding(sev, loc, cwe, poc, fix):
    return {"severity": sev, "lokasi": loc, "cwe": cwe, "poc": poc, "fix": fix}


REDIRECT_PARAMS = {"next", "redirect", "redirect_uri", "redirect_url", "url",
                   "return", "return_to", "returnurl", "dest", "destination",
                   "continue", "goto", "r", "u"}

FILE_PARAMS = {"file", "path", "page", "doc", "document", "template", "tpl",
               "include", "inc", "load", "read", "name", "download", "filename"}

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*\Wmysqli?_", r"MySqlException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"Microsoft OLE DB Provider for SQL Server", r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver", r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated", r"ORA-\d{5}",
    r"SQLite/JDBCDriver", r"SQLITE_ERROR", r"sqlite3.OperationalError",
    r"org\.hibernate\.", r"Syntax error.*in query expression",
]
SQL_ERR_RE = re.compile("|".join(SQL_ERRORS), re.I)


# ---------------------------------------------------------------------------
# Cek PASIF (default)
# ---------------------------------------------------------------------------

def cek_header_keamanan(url, rate):
    out = []
    r = http_get(url)
    wajib = {
        "Content-Security-Policy": ("CWE-693", "tambahkan CSP ketat (tanpa unsafe-inline)"),
        "X-Frame-Options": ("CWE-1021", "set X-Frame-Options / CSP frame-ancestors"),
        "Strict-Transport-Security": ("CWE-319", "aktifkan HSTS"),
        "X-Content-Type-Options": ("CWE-693", "set X-Content-Type-Options: nosniff"),
    }
    for h, (cwe, fix) in wajib.items():
        if not r.header(h):
            out.append(finding("LOW", url, cwe, f"header '{h}' hilang", fix))
    cookie = r.header("Set-Cookie")
    if cookie:
        if "httponly" not in cookie.lower():
            out.append(finding("LOW", url, "CWE-1004", "cookie tanpa HttpOnly", "set HttpOnly"))
        if "secure" not in cookie.lower():
            out.append(finding("LOW", url, "CWE-614", "cookie tanpa Secure", "set Secure"))
        if "samesite" not in cookie.lower():
            out.append(finding("LOW", url, "CWE-1275", "cookie tanpa SameSite", "set SameSite=Lax/Strict"))
    time.sleep(rate)
    return out


def cek_cors(url, rate):
    evil = "https://evil.example.com"
    r = http_get(url, headers={"Origin": evil})
    acao = r.header("Access-Control-Allow-Origin")
    acac = r.header("Access-Control-Allow-Credentials")
    out = []
    if acao == evil or acao == "*":
        sev = "HIGH" if (acac.lower() == "true" and acao == evil) else "MEDIUM"
        out.append(finding(sev, url, "CWE-942",
                           f"Origin dipantulkan (ACAO='{acao}', credentials='{acac}')",
                           "allowlist origin eksplisit; jangan reflect Origin + credentials"))
    time.sleep(rate)
    return out


def cek_reflected_xss(url, params, rate):
    out = []
    targets = params or ["q"]
    for pname in targets:
        marker = "zqx9k<svg/onload=1>'\""
        test = with_param(url, pname, marker)
        r = http_get(test)
        if marker in r.text:
            out.append(finding("MEDIUM", f"{url} [param={pname}]", "CWE-79",
                               "marker '<svg/onload=1>' dipantulkan tanpa encoding "
                               "(konfirmasi konteks HTML/JS secara manual)",
                               "output-encode kontekstual + CSP ketat"))
        elif marker.replace("<", "&lt;") not in r.text and marker[:5] in r.text:
            out.append(finding("INFO", f"{url} [param={pname}]", "CWE-79",
                               "sebagian input dipantulkan; angle-bracket ter-encode "
                               "(cek konteks atribut/JS)",
                               "pastikan encoding sesuai konteks"))
        time.sleep(rate)
    return out


def cek_open_redirect(url, params, rate):
    out = []
    cand = [p for p in (params or []) if p.lower() in REDIRECT_PARAMS] or \
           ([params[0]] if params else [])
    for pname in cand:
        for payload in ("https://evil.example.com/", "//evil.example.com/"):
            test = with_param(url, pname, payload)
            try:
                r = http_get(test, allow_redirects=False)
            except RuntimeError:
                continue
            loc = r.header("Location")
            if "evil.example.com" in loc and 300 <= r.status < 400:
                out.append(finding("MEDIUM", f"{url} [param={pname}]", "CWE-601",
                                   f"redirect 3xx ke domain luar via '{payload}' "
                                   f"(Location: {loc[:80]})",
                                   "validasi tujuan redirect dengan allowlist"))
                break
            time.sleep(rate)
    return out


# ---------------------------------------------------------------------------
# Cek AKTIF (butuh --active) — tetap read-only, bukti minimal
# ---------------------------------------------------------------------------

def cek_sqli(url, params, rate, time_based=False):
    """Deteksi SQLi: error-based, boolean-based, (opsional) time-based.
    TIDAK meng-extract data. Hanya menandai parameter yang rentan."""
    out = []
    if not params:
        return out
    base = http_get(url)
    base_len = base.length
    for pname in params:
        orig = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(pname, "1")

        # 1) error-based
        hit_error = False
        for inj in ("'", '"', "')", "'\"`"):
            r = http_get(with_param(url, pname, orig + inj))
            if SQL_ERR_RE.search(r.text):
                out.append(finding("HIGH", f"{url} [param={pname}]", "CWE-89",
                                   f"pesan error SQL muncul saat append {inj!r} "
                                   "(error-based, tanpa dump)",
                                   "pakai parameterized query / prepared statement"))
                hit_error = True
                break
            time.sleep(rate)
        if hit_error:
            continue

        # 2) boolean-based (bandingkan TRUE vs FALSE)
        r_true = http_get(with_param(url, pname, f"{orig}' AND '1'='1"))
        time.sleep(rate)
        r_false = http_get(with_param(url, pname, f"{orig}' AND '1'='2"))
        time.sleep(rate)
        sim_tf = similarity(r_true.text, r_false.text)
        sim_tbase = similarity(r_true.text, base.text)
        if r_true.status == r_false.status and sim_tf < 0.95 and sim_tbase > 0.90:
            out.append(finding("HIGH", f"{url} [param={pname}]", "CWE-89",
                               f"respons beda antara AND 1=1 vs AND 1=2 "
                               f"(sim={sim_tf:.2f}); kandidat boolean-blind SQLi",
                               "parameterized query; verifikasi manual lalu laporkan"))
            continue

        # 3) time-based (opsional; 1 probe, bounded)
        if time_based:
            delay = 3
            # payload generik lintas-DBMS sulit; pakai pola umum MySQL + ukur delay
            probe = f"{orig}' AND SLEEP({delay})-- "
            r = http_get(with_param(url, pname, probe))
            if r.elapsed >= delay - 0.5 and base.elapsed < delay - 0.5:
                out.append(finding("HIGH", f"{url} [param={pname}]", "CWE-89",
                                   f"delay ~{r.elapsed:.1f}s pada payload SLEEP({delay}) "
                                   "(kandidat time-based blind SQLi)",
                                   "parameterized query; verifikasi manual"))
            time.sleep(rate)
    return out


def cek_lfi(url, params, rate):
    """Deteksi path traversal/LFI via signature /etc/passwd. Read-only."""
    out = []
    cand = [p for p in (params or []) if p.lower() in FILE_PARAMS]
    if not cand:
        return out
    sig = re.compile(r"root:.*?:0:0:", re.S)
    payloads = ["../../../../../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"]
    for pname in cand:
        for pl in payloads:
            r = http_get(with_param(url, pname, pl))
            if sig.search(r.text):
                out.append(finding("HIGH", f"{url} [param={pname}]", "CWE-22",
                                   f"signature '/etc/passwd' terbaca via '{pl}' "
                                   "(read-only, tidak mengubah file)",
                                   "normalisasi path + jangkar direktori dasar + allowlist"))
                break
            time.sleep(rate)
    return out


# ---------------------------------------------------------------------------
# Cek butuh input tambahan
# ---------------------------------------------------------------------------

def cek_idor(url, cookie_a, cookie_b, rate):
    """Bandingkan respon URL yang sama dari 2 sesi berbeda.
    Kandidat IDOR bila sesi B bisa melihat resource milik sesi A."""
    out = []
    ra = http_get(url, cookie=cookie_a)
    time.sleep(rate)
    rb = http_get(url, cookie=cookie_b)
    time.sleep(rate)
    # kontrol: minta resource yang jelas butuh auth; kalau B == A dan 200 => curiga
    if ra.status == 200 and rb.status == 200:
        sim = similarity(ra.text, rb.text)
        if sim > 0.90 and ra.length > 100:
            out.append(finding("HIGH", url, "CWE-639",
                               f"sesi A & B menerima body hampir identik (sim={sim:.2f}, "
                               f"{ra.length}B) pada resource ber-id — kandidat IDOR",
                               "cek kepemilikan objek terhadap user login di server"))
        else:
            out.append(finding("INFO", url, "CWE-639",
                               f"respon A vs B berbeda (sim={sim:.2f}) — kemungkinan "
                               "authz benar; verifikasi manual id objek lain",
                               "lanjutkan uji IDOR manual pada id berbeda"))
    elif ra.status == 200 and rb.status in (401, 403, 404):
        out.append(finding("INFO", url, "CWE-639",
                           f"sesi B ditolak ({rb.status}) saat A diizinkan — authz tampak OK",
                           "tetap uji id objek lain milik B secara manual"))
    return out


def cek_user_enum(enum_url, user_ada, user_tdk, param, rate):
    """Bandingkan respon untuk user yang ADA vs TIDAK ADA (status/panjang/timing)."""
    out = []
    r1 = http_get(with_param(enum_url, param, user_ada))
    time.sleep(rate)
    r2 = http_get(with_param(enum_url, param, user_tdk))
    time.sleep(rate)
    beda = []
    if r1.status != r2.status:
        beda.append(f"status {r1.status} vs {r2.status}")
    if abs(r1.length - r2.length) > 40:
        beda.append(f"panjang {r1.length} vs {r2.length}")
    if abs(r1.elapsed - r2.elapsed) > 0.8:
        beda.append(f"timing {r1.elapsed:.2f}s vs {r2.elapsed:.2f}s")
    if beda:
        out.append(finding("MEDIUM", f"{enum_url} [param={param}]", "CWE-203",
                           "respon berbeda untuk user ada vs tidak ada: " + "; ".join(beda),
                           "seragamkan respon, status, dan timing; pesan generik"))
    return out


def cek_ssrf(url, params, callback, rate):
    """Blind SSRF: arahkan param ke listener milik Anda. TIDAK menembak metadata.
    Konfirmasi lewat hit di listener Anda sendiri."""
    out = []
    cand = [p for p in (params or []) if p.lower() in
            (REDIRECT_PARAMS | {"webhook", "callback", "avatar", "image", "img", "src", "feed", "proxy"})]
    if not cand:
        cand = params or []
    for pname in cand:
        http_get(with_param(url, pname, callback))
        out.append(finding("INFO", f"{url} [param={pname}]", "CWE-918",
                           f"dikirim permintaan agar server fetch {callback} — "
                           "PERIKSA listener Anda; ada hit = SSRF terkonfirmasi",
                           "allowlist host tujuan; blokir IP internal/metadata (169.254.169.254)"))
        time.sleep(rate)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def main():
    p = argparse.ArgumentParser(
        description="Scanner kerentanan web non-destruktif (HANYA target milik sendiri/berizin).")
    p.add_argument("target", help="URL target, mis. https://app-saya.com/item?id=1")
    p.add_argument("--active", action="store_true",
                   help="aktifkan cek SQLi + LFI (read-only, bukti minimal)")
    p.add_argument("--time-based", action="store_true",
                   help="sertakan probe SQLi time-based (1 probe SLEEP, lebih lambat)")
    p.add_argument("--param", action="append", default=[],
                   help="batasi/override parameter yang diuji (boleh diulang)")
    p.add_argument("--cookie-a", help="cookie sesi user A (untuk uji IDOR)")
    p.add_argument("--cookie-b", help="cookie sesi user B (untuk uji IDOR)")
    p.add_argument("--enum-url", help="URL endpoint untuk uji user enumeration")
    p.add_argument("--user-ada", help="identifier user yang pasti ada")
    p.add_argument("--user-tdk-ada", help="identifier user yang pasti tidak ada")
    p.add_argument("--enum-param", default="email", help="nama param enumerasi (default: email)")
    p.add_argument("--ssrf-callback", help="URL listener Anda untuk uji blind SSRF")
    p.add_argument("--rate", type=float, default=0.5, help="jeda antar-request detik (default: 0.5)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--yes-authorized", action="store_true",
                   help="konfirmasi bahwa target milik Anda / berizin (lewati prompt)")
    args = p.parse_args()

    if not _url_ok(args.target):
        sys.exit("URL tidak valid. Harus http:// atau https:// dengan host.")

    # Gate otorisasi
    if not args.yes_authorized:
        try:
            jawab = input(f"Konfirmasi: '{urlparse(args.target).netloc}' milik Anda "
                          f"atau dalam scope berizin? [ketik 'ya']: ").strip().lower()
        except EOFError:
            jawab = ""
        if jawab not in ("ya", "y", "yes"):
            sys.exit("Dibatalkan — tanpa otorisasi, tidak ada scan.")

    params = args.param or params_of(args.target)

    if not args.json:
        print(f"# scanner_kustom — NON-DESTRUKTIF | engine: "
              f"{'requests' if _HAVE_REQUESTS else 'urllib'}")
        print(f"# Target : {args.target}")
        print(f"# Params : {params or '(tidak ada query param)'}")
        print(f"# Mode   : {'AKTIF (SQLi+LFI)' if args.active else 'pasif'}"
              f"{' + time-based' if args.time_based else ''}\n")

    temuan = []

    def jalankan(nama, fn):
        try:
            temuan.extend(fn())
        except RuntimeError as e:
            if not args.json:
                print(f"# [{nama}] gagal request: {e}")

    # pasif (selalu)
    jalankan("headers", lambda: cek_header_keamanan(args.target, args.rate))
    jalankan("cors", lambda: cek_cors(args.target, args.rate))
    jalankan("xss", lambda: cek_reflected_xss(args.target, params, args.rate))
    jalankan("open-redirect", lambda: cek_open_redirect(args.target, params, args.rate))

    # aktif
    if args.active:
        jalankan("sqli", lambda: cek_sqli(args.target, params, args.rate, args.time_based))
        jalankan("lfi", lambda: cek_lfi(args.target, params, args.rate))

    # butuh input
    if args.cookie_a and args.cookie_b:
        jalankan("idor", lambda: cek_idor(args.target, args.cookie_a, args.cookie_b, args.rate))
    if args.enum_url and args.user_ada and args.user_tdk_ada:
        jalankan("user-enum", lambda: cek_user_enum(
            args.enum_url, args.user_ada, args.user_tdk_ada, args.enum_param, args.rate))
    if args.ssrf_callback:
        jalankan("ssrf", lambda: cek_ssrf(args.target, params, args.ssrf_callback, args.rate))

    temuan.sort(key=lambda t: SEV_ORDER.get(t["severity"], 9))

    if args.json:
        print(json.dumps(temuan, ensure_ascii=False, indent=2))
        return

    if temuan:
        print("## Temuan ([SEVERITY] | lokasi | CWE | PoC | FIX):")
        for t in temuan:
            print(f"[{t['severity']}] | {t['lokasi']} | {t['cwe']} | {t['poc']} | {t['fix']}")
        ring = {}
        for t in temuan:
            ring[t["severity"]] = ring.get(t["severity"], 0) + 1
        print("\n## Ringkasan: " + ", ".join(f"{k}={v}" for k, v in sorted(
            ring.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))))
        print("## Catatan: semua temuan adalah KANDIDAT — verifikasi manual & "
              "reproduksi sebelum dilaporkan. Tidak ada data yang di-dump/diubah.")
    else:
        print("## Tidak ada temuan pada cek ini (bukan berarti aman — lanjut uji manual).")


def _url_ok(u):
    try:
        pr = urlparse(u)
        return pr.scheme in ("http", "https") and bool(pr.netloc)
    except Exception:
        return False


if __name__ == "__main__":
    main()
