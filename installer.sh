#!/usr/bin/env bash
# =============================================================================
#  installer.sh  –  Android APK Patcher  v3.0
#  Installs all dependencies on Termux (Android) and Debian/Ubuntu Linux.
#  Fixes common androguard + frida install failures specific to Termux.
# =============================================================================
set -euo pipefail

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[x]${RESET} $*"; }
head()  {
    echo -e "\n${BOLD}${CYAN}--------------------------------------------------${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}${CYAN}--------------------------------------------------${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Detect environment
# ─────────────────────────────────────────────────────────────────────────────
IS_TERMUX=false
IS_LINUX=false
ARCH=$(uname -m)

if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then
    IS_TERMUX=true
elif [ "$(uname -s)" = "Linux" ]; then
    IS_LINUX=true
fi

head "Android APK Patcher – Dependency Installer"
info "Environment : $( $IS_TERMUX && echo 'Termux (Android)' || echo 'Linux')"
info "Architecture: $ARCH"

# ─────────────────────────────────────────────────────────────────────────────
#  TERMUX
# ─────────────────────────────────────────────────────────────────────────────
install_termux() {
    head "Termux: Updating packages"
    pkg update -y && pkg upgrade -y

    head "Termux: Core packages"
    # Try openjdk versions in order (package name varies by Termux repo state)
    pkg install -y openjdk-21 2>/dev/null \
    || pkg install -y openjdk-17 2>/dev/null \
    || {
        warn "openjdk-21/17 not found via pkg – trying termux-apt-repo..."
        # Some Termux setups need the full package name
        pkg install -y "openjdk-21-jdk" 2>/dev/null \
        || pkg install -y "openjdk-17-jdk" 2>/dev/null \
        || {
            warn "Java not found in pkg repos."
            warn "Install manually:  pkg install openjdk-21"
            warn "Or download from:  https://github.com/termux/termux-packages"
        }
    }

    pkg install -y \
        python python-pip \
        binutils build-essential clang \
        libffi openssl \
        libxml2 libxslt \
        python-lxml \
        git curl wget unzip zip \
    || true

    head "Termux: Python base"
    pip install --upgrade pip setuptools wheel

    # ── Androguard ─────────────────────────────────────────────────────────────
    # Common Termux failures:
    #   1. lxml native build fails -> use system python-lxml from pkg
    #   2. networkx version conflict -> pin to compatible version
    #   3. Cython headers missing -> install build-essential first
    # ── Androguard ─────────────────────────────────────────────────────────────
    # androguard 4.x pulls in frida, matplotlib, ipython, dataset as hard deps –
    # these are enormous and frida can't be built on Termux without a pre-built wheel.
    # androguard 3.3.5 is fully sufficient for Ana.py and has no heavy deps.
    head "Termux: androguard 3.3.5 (lightweight, Termux-compatible)"

    pip install --upgrade \
        "networkx>=2.6,<3.2" \
        "colorama>=0.4" \
        "future>=0.18" \
        "pyelftools>=0.29" \
        "pycryptodome>=3.15" \
        "loguru" "pyyaml" "click" "asn1crypto" \
    || true

    # Prefer 3.3.5: lighter deps, stable API, works on Python 3.11-3.13
    pip install "androguard==3.3.5" 2>/dev/null \
    || {
        # If 3.3.5 not available, try latest but pin out frida/matplotlib
        warn "3.3.5 not available – installing latest with constrained deps..."
        pip install androguard \
            --no-deps \
        && pip install \
            "networkx>=2.6,<3.2" lxml "pycryptodome>=3.15" \
            loguru pyyaml click asn1crypto apkInspector mutf8 \
        || pip install androguard --no-build-isolation \
        || err "androguard install failed. See TROUBLESHOOTING."
    }

    # ── Frida ──────────────────────────────────────────────────────────────────
    # Common Termux failures:
    #   1. No pre-built wheel for the exact Python/ABI combo -> download directly
    #   2. Building frida-core from source fails / takes hours -> never do this
    #   3. frida-server version mismatch -> must match wheel version
    head "Termux: frida (pre-built wheel)"
    # Frida wheel naming changed across versions.  We try several known patterns:
    #   v16.x:  frida-16.x.y-cp3NN-cp3NN-android-arm64.whl      (old naming)
    #   v17.x:  frida-17.x.y-cp3NN-cp3NN-linux_aarch64.whl      (new naming, works on Termux)
    # Strategy: try the latest stable v16 wheel first (most stable on Termux),
    # then try the pkg frida if available, then skip gracefully.

    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")

    # 1. Try pkg frida (fastest, pre-compiled for Termux)
    if pkg install -y python-frida 2>/dev/null; then
        ok "frida installed via pkg (python-frida)"
    else
        # 2. Try downloading pre-built wheel from GitHub
        #    Frida 16.2.1 – last release with android-arm64 naming
        FRIDA_VER="16.2.1"
        # Two possible name patterns depending on frida release
        WHEEL_OLD="frida-${FRIDA_VER}-cp${PY_VER}-cp${PY_VER}-android-arm64.whl"
        WHEEL_NEW="frida-${FRIDA_VER}-cp${PY_VER}-cp${PY_VER}-linux_aarch64.whl"
        BASE_URL="https://github.com/frida/frida/releases/download/${FRIDA_VER}"

        INSTALLED_FRIDA=false
        for WHEEL in "$WHEEL_OLD" "$WHEEL_NEW"; do
            info "Trying frida wheel: $WHEEL"
            if curl -fL "${BASE_URL}/${WHEEL}" -o "/tmp/${WHEEL}" 2>/dev/null; then
                pip install "/tmp/${WHEEL}" && { ok "frida installed: $WHEEL"; INSTALLED_FRIDA=true; break; }
            fi
        done

        # 3. Try pip with --only-binary (won't build from source)
        if ! $INSTALLED_FRIDA; then
            warn "Pre-built wheels for py${PY_VER} not found for frida ${FRIDA_VER}."
            warn "Trying pip --only-binary (no source build)..."
            pip install frida --only-binary :all: 2>/dev/null \
            && { ok "frida installed via pip binary."; INSTALLED_FRIDA=true; } \
            || warn "frida not installed – Ana.py works without it."
        fi

        if $INSTALLED_FRIDA; then
            pip install frida-tools --only-binary :all: 2>/dev/null \
                || warn "frida-tools not installed (optional)."
        fi
    fi

    # ── apktool ────────────────────────────────────────────────────────────────
    head "Termux: apktool"
    LBIN="$HOME/.local/bin"
    mkdir -p "$LBIN"
    if ! command -v apktool &>/dev/null && [ ! -f "$LBIN/apktool.jar" ]; then
        VER="2.9.3"
        BASE="https://github.com/iBotPeaches/Apktool/releases/download/v${VER}"
        RAW="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux"
        info "Downloading apktool ${VER}..."
        curl -fL "${BASE}/apktool_${VER}.jar" -o "${LBIN}/apktool.jar"
        curl -fL "${RAW}/apktool"             -o "${LBIN}/apktool"
        chmod +x "${LBIN}/apktool"
        ok "apktool installed at ${LBIN}/apktool"
        # Add to PATH for current session
        export PATH="$PATH:$LBIN"
        # Persist
        grep -qxF 'export PATH="$PATH:$HOME/.local/bin"' ~/.bashrc \
            || echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
    else
        ok "apktool already present."
    fi

    # ── Signing tools ──────────────────────────────────────────────────────────
    head "Termux: signing tools"
    pkg install -y apksigner aapt2 android-tools 2>/dev/null || true

    pip install colorama --upgrade 2>/dev/null || true

    ok "Termux setup complete!"
    _summary
}

# ─────────────────────────────────────────────────────────────────────────────
#  LINUX  (Debian/Ubuntu/Fedora/Arch)
# ─────────────────────────────────────────────────────────────────────────────
install_linux() {
    head "Linux: System packages"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            python3 python3-pip python3-venv python3-dev python3-lxml \
            openjdk-17-jre-headless \
            build-essential libffi-dev libssl-dev libxml2-dev libxslt-dev \
            wget curl unzip zip git
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y \
            python3 python3-pip python3-lxml python3-devel \
            java-17-openjdk-headless gcc make \
            libffi-devel openssl-devel libxml2-devel libxslt-devel \
            wget curl unzip zip git
    elif command -v pacman &>/dev/null; then
        sudo pacman -Syu --noconfirm \
            python python-pip python-lxml \
            jdk17-openjdk base-devel libffi openssl \
            wget curl unzip zip git
    fi

    head "Linux: Python packages"
    pip3 install --upgrade pip setuptools wheel
    pip3 install \
        androguard \
        frida frida-tools \
        colorama \
        "lxml>=4.9.0" \
        "networkx>=2.6" \
        "pyelftools>=0.29" \
        "pycryptodome>=3.15" \
        loguru pyyaml click asn1crypto \
    || warn "Some packages failed – check output above."

    head "Linux: apktool"
    if ! command -v apktool &>/dev/null; then
        VER="2.9.3"
        sudo curl -fL \
            "https://github.com/iBotPeaches/Apktool/releases/download/v${VER}/apktool_${VER}.jar" \
            -o /usr/local/bin/apktool.jar
        sudo curl -fL \
            "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
            -o /usr/local/bin/apktool
        sudo chmod +x /usr/local/bin/apktool
        ok "apktool installed."
    else
        ok "apktool already present."
    fi

    ok "Linux setup complete!"
    _summary
}

# ─────────────────────────────────────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────────────────────────────────────
_summary() {
    head "Verification"

    python3 -c "import androguard; print('androguard', androguard.__version__)" 2>/dev/null \
        && ok "androguard OK" || err "androguard MISSING"

    python3 -c "import frida; print('frida', frida.__version__)" 2>/dev/null \
        && ok "frida OK" || warn "frida missing (optional)"

    java -version 2>&1 | head -1 | grep -q "version" \
        && ok "java OK" || err "java MISSING (required for apktool)"

    { command -v apktool &>/dev/null || [ -f "$HOME/.local/bin/apktool.jar" ]; } \
        && ok "apktool OK" || err "apktool MISSING"

    command -v apksigner &>/dev/null && ok "apksigner OK" || warn "apksigner missing (fallback: jarsigner)"
    command -v zipalign  &>/dev/null && ok "zipalign OK"  || warn "zipalign missing (optional)"

    head "Quick Start"
    echo -e "  ${BOLD}python Ana.py app.apk${RESET}                   # full auto"
    echo -e "  ${BOLD}python Ana.py app.apk --detect-only${RESET}     # scan only"
    echo -e "  ${BOLD}python Ana.py app.apk --variant A C${RESET}     # variants A and C"
    echo -e "  ${BOLD}python Ana.py app.apk --no-sign${RESET}         # unsigned output"

    head "Troubleshooting"
    cat <<'HELP'

JAVA
----
 "Unable to locate package openjdk-17":
   pkg install openjdk-21         # Termux now ships 21, not 17
   # If that also fails:
   pkg update && pkg upgrade && pkg install openjdk-21

ANDROGUARD
----------
 androguard 4.x pulls in frida/matplotlib/ipython (huge, breaks on Termux):
   pip install "androguard==3.3.5"    # lightweight, works perfectly

 lxml build fails on Termux:
   pkg install python-lxml
   pip install androguard==3.3.5

 networkx conflict:
   pip install "networkx>=2.6,<3.2" --force-reinstall

FRIDA
-----
 No matching wheel:
   Go to https://github.com/frida/frida/releases
   Download: frida-<ver>-cp<pyver>-cp<pyver>-android-arm64.whl
   Install:  pip install frida-*.whl

 frida-server version mismatch:
   frida wheel version must EXACTLY match frida-server on device

 Build from source hangs (never do this on Termux):
   Always use --only-binary :all: or pre-built wheel

APKTOOL
-------
 OutOfMemoryError:
   export JAVA_OPTS="-Xmx2g"

 Resource decode errors (brut.androlib):
   Ana.py auto-retries with --no-res flag

SIGNING
-------
 Keystore not found:
   keytool -genkey -v -keystore my.keystore -alias mykey \
           -keyalg RSA -keysize 2048 -validity 10000
   Or: python Ana.py app.apk --no-sign

GENERAL
-------
 Debug mode: python Ana.py app.apk --keep-work 2>&1 | tee ana.log
 Re-run:     bash installer.sh
HELP
}

# ─────────────────────────────────────────────────────────────────────────────
#  Dispatch
# ─────────────────────────────────────────────────────────────────────────────
if $IS_TERMUX; then
    install_termux
elif $IS_LINUX; then
    install_linux
else
    warn "Unknown OS – attempting generic pip install..."
    pip install androguard frida frida-tools colorama lxml networkx \
                pyelftools pycryptodome
    _summary
fi
