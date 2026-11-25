#!/usr/bin/env python3
"""
scanner_kustom.py — scanner keamanan web ringan & NON-DESTRUKTIF.

HANYA untuk target milik sendiri atau yang berizin tertulis.
Cek dasar: header keamanan, flag cookie, reflected XSS, CORS, open redirect.

Pemakaian:
    python3 scanner_kustom.py https://app-saya.com
    python3 scanner_kustom.py https://app-saya.com --param q --rate 1.0

Butuh: pip install requests
"""
import argparse
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("Butuh modul 'requests'. Jalankan: pip install requests")


def cek_header_keamanan(sess, url):
    temuan = []
    r = sess.get(url, timeout=10)
    wajib = {
        "Content-Security-Policy": ("CWE-693", "tambahkan CSP yang ketat"),
        "X-Frame-Options": ("CWE-1021", "tambahkan X-Frame-Options/frame-ancestors (anti-clickjacking)"),
        "Strict-Transport-Security": ("CWE-319", "aktifkan HSTS"),
        "X-Content-Type-Options": ("CWE-693", "set X-Content-Type-Options: nosniff"),
    }
    for h, (cwe, fix) in wajib.items():
        if h not in r.headers:
            temuan.append(f"[LOW] | {url} | {cwe} | header '{h}' hilang | {fix}")
    cookie = r.headers.get("Set-Cookie", "")
    if cookie:
        if "HttpOnly" not in cookie:
            temuan.append(f"[LOW] | {url} | CWE-1004 | cookie tanpa HttpOnly | set HttpOnly")
        if "Secure" not in cookie:
            temuan.append(f"[LOW] | {url} | CWE-614 | cookie tanpa Secure | set Secure")
        if "SameSite" not in cookie:
            temuan.append(f"[LOW] | {url} | CWE-1275 | cookie tanpa SameSite | set SameSite=Lax/Strict")
    return temuan


def cek_reflected_xss(sess, url, param):
    marker = "zqx<svg>123"
    r = sess.get(url, params={param: marker}, timeout=10)
    if marker in r.text:
        return [f"[MEDIUM] | {url}?{param} | CWE-79 | input dipantulkan tanpa encode "
                f"(cek konteks utk XSS) | output-encode kontekstual + CSP"]
    return []


def cek_cors(sess, url):
    evil = "https://evil.example.com"
    r = sess.get(url, headers={"Origin": evil}, timeout=10)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == evil or acao == "*":
        sev = "HIGH" if acac.lower() == "true" and acao == evil else "MEDIUM"
        return [f"[{sev}] | {url} | CWE-942 | Origin dipantulkan (ACAO='{acao}', "
                f"credentials='{acac}') | allowlist origin, jangan reflect"]
    return []


def cek_open_redirect(sess, url, param):
    evil = "https://evil.example.com"
    try:
        r = sess.get(url, params={param: evil}, timeout=10, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if evil in loc:
            return [f"[MEDIUM] | {url}?{param} | CWE-601 | redirect ke domain luar | "
                    f"allowlist tujuan redirect"]
    except requests.RequestException:
        pass
    return []


def main():
    p = argparse.ArgumentParser(description="Scanner keamanan web non-destruktif (target milik sendiri).")
    p.add_argument("target", help="URL target, mis. https://app-saya.com")
    p.add_argument("--param", default="q", help="nama parameter untuk uji XSS/redirect (default: q)")
    p.add_argument("--rate", type=float, default=0.5, help="jeda antar-request detik (default: 0.5)")
    args = p.parse_args()

    print("# Scanner hanya untuk target milik sendiri/berizin. Mode non-destruktif.")
    print(f"# Target: {args.target}\n")

    sess = requests.Session()
    sess.headers.update({"User-Agent": "audit-internal/1.0"})

    semua = []
    for fungsi in (
        lambda: cek_header_keamanan(sess, args.target),
        lambda: cek_cors(sess, args.target),
        lambda: cek_reflected_xss(sess, args.target, args.param),
        lambda: cek_open_redirect(sess, args.target, args.param),
    ):
        try:
            semua.extend(fungsi())
        except requests.RequestException as e:
            print(f"# gagal request: {e}")
        time.sleep(args.rate)

    if semua:
        print("## Temuan ([SEVERITY] | lokasi | CWE | PoC | FIX):")
        for t in semua:
            print(t)
    else:
        print("## Tidak ada temuan pada cek dasar ini (bukan berarti aman — lanjutkan uji manual).")


if __name__ == "__main__":
    main()
