#!/usr/bin/env bash
# install_tools.sh — pasang arsenal tool bug bounty ke $PATH (best-effort).
#
# HANYA jalankan di environment yang Anda kontrol / diizinkan memasang software,
# dan hanya untuk dipakai pada target milik sendiri / dalam scope berizin.
#
# Idempotent: tool yang sudah ada dilewati. Aman diulang.
# Memasang lewat: package manager (apt/dnf/brew/pkg) + pipx/pip + go install +
# git clone (untuk tool berbasis skrip). Tidak ada `curl | bash` dari sumber
# tak resmi.
#
# Pemakaian:
#   bash install_tools.sh            # pasang semua yang hilang
#   bash install_tools.sh --check    # hanya laporkan OK/MISS, tanpa memasang
#   bash install_tools.sh nmap sqlmap nuclei   # pasang subset tertentu
#
# Setelah selesai, pastikan baris PATH berikut ada di ~/.bashrc / ~/.zshrc:
#   export PATH="$HOME/go/bin:$HOME/.local/bin:$HOME/.bb-tools/bin:$PATH"

set -u

TOOLS_DIR="${BB_TOOLS_DIR:-$HOME/.bb-tools}"
BIN_DIR="$TOOLS_DIR/bin"
mkdir -p "$BIN_DIR"

GOBIN="$HOME/go/bin"
LOCALBIN="$HOME/.local/bin"
export PATH="$GOBIN:$LOCALBIN:$BIN_DIR:$PATH"

CHECK_ONLY=0
SELECT=()
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    -*) echo "opsi tak dikenal: $a" ;;
    *) SELECT+=("$a") ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
want() {  # want <tool>: true jika tool ini dipilih (atau tak ada filter)
  [ ${#SELECT[@]} -eq 0 ] && return 0
  for s in "${SELECT[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}
log()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
miss() { printf '\033[33m[MISS]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m[ERR]\033[0m %s\n' "$*"; }

# ---- deteksi package manager & sudo -------------------------------------
SUDO=""
[ "$(id -u 2>/dev/null)" != "0" ] && have sudo && SUDO="sudo"

PM=""
if   have apt-get; then PM="apt"
elif have dnf;     then PM="dnf"
elif have pacman;  then PM="pacman"
elif have brew;    then PM="brew"
elif have pkg;     then PM="pkg"      # termux / *BSD
fi
log "package manager: ${PM:-'(tidak terdeteksi)'}   sudo: ${SUDO:-'(tidak)'}"

pm_install() {  # pm_install <paket...>
  [ -z "$PM" ] && return 1
  case "$PM" in
    apt)    $SUDO apt-get update -qq >/dev/null 2>&1; $SUDO apt-get install -y "$@" ;;
    dnf)    $SUDO dnf install -y "$@" ;;
    pacman) $SUDO pacman -Sy --noconfirm "$@" ;;
    brew)   brew install "$@" ;;
    pkg)    $SUDO pkg install -y "$@" ;;
  esac
}

ensure_pipx() {
  have pipx && return 0
  log "memasang pipx…"
  pm_install pipx >/dev/null 2>&1
  have pipx && return 0
  python3 -m pip install --user pipx >/dev/null 2>&1 && python3 -m pipx ensurepath >/dev/null 2>&1
  have pipx
}

pipx_install() {  # pipx_install <nama-pipx> <binari>
  local pkg="$1" bin="${2:-$1}"
  have "$bin" && { ok "$bin (sudah ada)"; return 0; }
  if ensure_pipx; then
    pipx install "$pkg" >/dev/null 2>&1 && { ok "$bin (pipx)"; return 0; }
  fi
  python3 -m pip install --user "$pkg" >/dev/null 2>&1 && { ok "$bin (pip --user)"; return 0; }
  err "$bin gagal dipasang (pipx/pip)"; return 1
}

go_install() {  # go_install <binari> <module@ver>
  local bin="$1" mod="$2"
  have "$bin" && { ok "$bin (sudah ada)"; return 0; }
  have go || { err "$bin butuh Go — pasang Go dulu (lihat §Go)"; return 1; }
  log "go install $mod"
  GOBIN="$GOBIN" go install "$mod" >/dev/null 2>&1 && { ok "$bin (go)"; return 0; }
  err "$bin gagal (go install $mod)"; return 1
}

git_tool() {  # git_tool <binari> <repo-url> <entrypoint-relatif> [pip-reqs:1]
  local bin="$1" repo="$2" entry="$3" reqs="${4:-0}"
  have "$bin" && { ok "$bin (sudah ada)"; return 0; }
  local dir="$TOOLS_DIR/$bin"
  if [ ! -d "$dir/.git" ]; then
    log "git clone $repo"
    git clone --depth 1 "$repo" "$dir" >/dev/null 2>&1 || { err "$bin clone gagal"; return 1; }
  fi
  [ "$reqs" = "1" ] && [ -f "$dir/requirements.txt" ] && \
    python3 -m pip install --user -r "$dir/requirements.txt" >/dev/null 2>&1
  # buat shim di BIN_DIR
  cat > "$BIN_DIR/$bin" <<EOF
#!/usr/bin/env bash
exec "$dir/$entry" "\$@"
EOF
  chmod +x "$BIN_DIR/$bin" "$dir/$entry" 2>/dev/null
  have "$bin" && { ok "$bin (git shim → $dir/$entry)"; return 0; }
  err "$bin shim gagal"; return 1
}

# =========================================================================
# CHECK-ONLY
# =========================================================================
ALL="subfinder amass httpx katana gau waybackurls nmap whatweb ffuf dirsearch \
gobuster feroxbuster nuclei nikto sqlmap commix SSTImap dalfox xsstrike \
jwt_tool testssl.sh shcheck CORScanner gitleaks trufflehog semgrep bandit njsscan"

if [ "$CHECK_ONLY" = "1" ]; then
  for t in $ALL; do have "$t" && ok "$t" || miss "$t"; done
  exit 0
fi

# =========================================================================
# PASANG
# =========================================================================

# --- Go toolchain (dibutuhkan untuk tool ProjectDiscovery/dalfox/dll.) ----
if ! have go; then
  want go && { log "memasang Go toolchain…"; pm_install golang >/dev/null 2>&1 || pm_install go >/dev/null 2>&1; }
fi
have go && ok "go $(go version 2>/dev/null | awk '{print $3}')" || miss "go (tool berbasis Go akan dilewati)"

# --- System packages (apt/brew/…) ----------------------------------------
want nmap     && { have nmap     && ok "nmap (sudah ada)"     || { pm_install nmap     >/dev/null 2>&1 && ok nmap     || err nmap; }; }
want nikto    && { have nikto    && ok "nikto (sudah ada)"    || { pm_install nikto    >/dev/null 2>&1 && ok nikto    || err nikto; }; }
want whatweb  && { have whatweb  && ok "whatweb (sudah ada)"  || { pm_install whatweb  >/dev/null 2>&1 && ok whatweb  || err whatweb; }; }
want gobuster && { have gobuster && ok "gobuster (sudah ada)" || { pm_install gobuster >/dev/null 2>&1 && ok gobuster || go_install gobuster github.com/OJ/gobuster/v3@latest; }; }
want amass    && { have amass    && ok "amass (sudah ada)"    || { pm_install amass    >/dev/null 2>&1 && ok amass    || go_install amass github.com/owasp-amass/amass/v4/...@master; }; }
want feroxbuster && { have feroxbuster && ok "feroxbuster (sudah ada)" || { pm_install feroxbuster >/dev/null 2>&1 && ok feroxbuster || miss "feroxbuster (pasang via cargo/release manual)"; }; }

# --- Go tools (ProjectDiscovery dkk.) -------------------------------------
want subfinder   && go_install subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
want httpx       && go_install httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
want katana      && go_install katana       github.com/projectdiscovery/katana/cmd/katana@latest
want nuclei      && go_install nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
want gau         && go_install gau          github.com/lc/gau/v2/cmd/gau@latest
want waybackurls && go_install waybackurls  github.com/tomnomnom/waybackurls@latest
want ffuf        && go_install ffuf         github.com/ffuf/ffuf/v2@latest
want dalfox      && go_install dalfox       github.com/hahwul/dalfox/v2@latest
want gitleaks    && { have gitleaks && ok "gitleaks (sudah ada)" || go_install gitleaks github.com/gitleaks/gitleaks/v8@latest; }
want trufflehog  && { have trufflehog && ok "trufflehog (sudah ada)" || go_install trufflehog github.com/trufflesecurity/trufflehog/v3@latest; }

# --- Python tools (pipx) --------------------------------------------------
want semgrep  && pipx_install semgrep semgrep
want bandit   && pipx_install bandit bandit
want njsscan  && pipx_install njsscan njsscan
want dirsearch && pipx_install dirsearch dirsearch
want sqlmap   && { have sqlmap && ok "sqlmap (sudah ada)" || pipx_install sqlmap sqlmap || \
                   git_tool sqlmap https://github.com/sqlmapproject/sqlmap sqlmap.py; }

# --- Git-clone tools (skrip) ----------------------------------------------
want commix   && git_tool commix   https://github.com/commixproject/commix commix.py
want SSTImap  && git_tool SSTImap  https://github.com/vladko312/SSTImap sstimap.py 1
want xsstrike && git_tool xsstrike https://github.com/s0md3v/XSStrike xsstrike.py 1
want jwt_tool && git_tool jwt_tool https://github.com/ticarpi/jwt_tool jwt_tool.py 1
want testssl.sh && git_tool testssl.sh https://github.com/drwetter/testssl.sh testssl.sh
want shcheck    && git_tool shcheck    https://github.com/santoru/shcheck shcheck.py
want CORScanner && git_tool CORScanner https://github.com/chenjj/CORScanner cors_scan.py 1

# =========================================================================
# RINGKAS
# =========================================================================
echo
log "ringkasan akhir (OK = terpasang di PATH sesi ini):"
MISSING=""
for t in $ALL; do
  if have "$t"; then ok "$t"; else miss "$t"; MISSING="$MISSING $t"; fi
done

echo
if [ -n "$MISSING" ]; then
  err "masih MISS:$MISSING"
  echo "   Penyebab umum: tidak ada akses jaringan keluar, Go tidak terpasang,"
  echo "   atau tool butuh pemasangan manual (mis. feroxbuster via cargo)."
fi
echo
echo ">> WAJIB tambahkan ke ~/.bashrc / ~/.zshrc lalu buka shell baru:"
echo "   export PATH=\"\$HOME/go/bin:\$HOME/.local/bin:$BIN_DIR:\$PATH\""
echo
echo ">> Verifikasi ulang kapan saja: bash install_tools.sh --check"
echo ">> Ingat: pakai hanya pada target milik sendiri / dalam scope berizin."
