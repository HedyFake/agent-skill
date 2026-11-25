"""Hermes plugin: Auditor Keamanan Web (defensif).

Mendaftarkan slash command:
  /audit [codereview|blackbox|tools]  -> tampilkan panduan audit
  /audit-sast [path]                  -> jalankan semgrep SAST (non-destruktif)

Hanya untuk kode/aplikasi milik sendiri atau yang berizin.
"""
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PLUGIN_DIR / "skills"

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
    target = (raw_args or ".").strip()
    # Jalankan lewat tool 'terminal' agar melewati pipeline approval & redaksi Hermes.
    return ctx.dispatch_tool(
        "terminal",
        {"command": f"semgrep --config=auto {target}"},
    )


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
