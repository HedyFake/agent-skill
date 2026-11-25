"""Hermes plugin: Auditor Keamanan Web (defensif).

Mendaftarkan slash command:
  /audit [codereview|blackbox|tools]  -> tampilkan panduan audit
  /audit-sast [path]                  -> jalankan semgrep SAST pada kode (non-destruktif)
  /audit-url <url> [full]             -> pindai URL website (non-destruktif)

HANYA untuk kode/aplikasi milik sendiri atau yang berizin tertulis.
"""
import shlex
from pathlib import Path
from urllib.parse import urlparse

PLUGIN_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PLUGIN_DIR / "skills"
SCANNER = PLUGIN_DIR / "scripts" / "scanner_kustom.py"

# Peta argumen -> nama berkas panduan
_PANDUAN = {
    "codereview": "audit-keamanan-web-codereview.md",
    "blackbox": "audit-keamanan-web-blackbox.md",
    "tools": "tools-keamanan-web.md",
}


def _cari_berkas(nama):
    """Cari berkas di folder skills/ maupun di root repo (tahan dua layout)."""
    for base in (SKILLS_DIR, PLUGIN_DIR):
        f = base / nama
        if f.exists():
            return f.read_text(encoding="utf-8")
    return f"(berkas '{nama}' tidak ditemukan di plugin)"


def _cmd_audit(ctx, raw_args):
    arg = (raw_args or "").strip().lower()
    nama = _PANDUAN.get(arg, _PANDUAN["codereview"])
    if arg and arg not in _PANDUAN:
        return ("Pemakaian: /audit [codereview|blackbox|tools]\n\n"
                + _cari_berkas(_PANDUAN["codereview"]))
    return _cari_berkas(nama)


def _cmd_sast(ctx, raw_args):
    target = (raw_args or ".").strip() or "."
    # Perlakukan input HANYA sebagai path; tolak yang menyerupai opsi (option injection).
    if target.startswith("-"):
        return "Path tidak boleh diawali '-'. Contoh: /audit-sast ./src"
    # shlex.quote menetralkan metakarakter shell; input tidak pernah mentah ke shell.
    return ctx.dispatch_tool(
        "terminal",
        {"command": f"semgrep --config=auto {shlex.quote(target)}"},
    )


def _url_valid(u):
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _cmd_url(ctx, raw_args):
    """Pindai URL website secara non-destruktif.

    /audit-url https://app-milikmu.com          -> scan dasar (scanner bawaan)
    /audit-url https://app-milikmu.com full      -> + testssl/nikto/nuclei bila terpasang
    """
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

    # Scan dasar: scanner bawaan plugin (non-destruktif, hanya butuh python3+requests).
    cmd = f"echo '=== Scan non-destruktif untuk {url} (pastikan ini milikmu/berizin) ==='; "
    cmd += f"python3 {q(str(SCANNER))} {url_q}"

    if mode == "full":
        # Tambahan tools DETEKSI (bukan eksploitasi). Dilewati otomatis bila tool tak ada.
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


def register(ctx):
    """Dipanggil sekali saat Hermes start."""
    ctx.register_command(
        "audit",
        lambda raw: _cmd_audit(ctx, raw),
        description="Tampilkan panduan audit keamanan web: /audit [codereview|blackbox|tools]",
    )
    ctx.register_command(
        "audit-sast",
        lambda raw: _cmd_sast(ctx, raw),
        description="Jalankan semgrep SAST pada path (default: .) — butuh semgrep terpasang",
    )
    ctx.register_command(
        "audit-url",
        lambda raw: _cmd_url(ctx, raw),
        description="Pindai URL website non-destruktif: /audit-url <url> [full]",
    )

    # Opsional: daftarkan sebagai skill Hermes bila API tersedia. Dibungkus
    # try/except agar plugin tetap dimuat meski signature berbeda antar-versi.
    try:
        for nama, berkas in (
            ("audit-codereview", _PANDUAN["codereview"]),
            ("audit-blackbox", _PANDUAN["blackbox"]),
        ):
            path = SKILLS_DIR / berkas
            if path.exists():
                ctx.register_skill(name=nama, path=str(path))
    except Exception:
        pass
