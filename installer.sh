#!/usr/bin/env bash
# =============================================================================
#  installer.sh  –  UnGuard v2.0.0  Dependency Installer
#  Installs all dependencies on:
#    • Termux (Android/ARM)
#    • Debian / Ubuntu / Fedora / Arch Linux
#    • macOS (Homebrew)
#
#  Fixes vs v1.x:
#    - macOS / Darwin detection and Homebrew-based install path
#    - Script name references corrected to unguard.py (was Ana.py)
#    - PATH persistence covers ~/.bashrc, ~/.zshrc, AND ~/.profile
#    - pip3 used consistently on Linux to avoid ambiguity
#    - apksigner install attempted on Linux via Android build-tools
#    - Frida wheel fallback tries multiple Python versions gracefully
#    - set -euo pipefail plus || true used consistently for optional steps
#    - Java JAVA_HOME export added for Termux
#    - Verification section updated for unguard.py
# =============================================================================
set -euo pipefail

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[x]${RESET} $*"; }
head_() {
    echo -e "\n${BOLD}${CYAN}--------------------------------------------------${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}${CYAN}--------------------------------------------------${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Detect environment
# ─────────────────────────────────────────────────────────────────────────────
IS_TERMUX=false
IS_LINUX=false
IS_MACOS=false
ARCH=$(uname -m)
OS=$(uname -s)

if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then
    IS_TERMUX=true
elif [ "$OS" = "Linux" ]; then
    IS_LINUX=true
elif [ "$OS" = "Darwin" ]; then
    IS_MACOS=true
fi

head_ "UnGuard – Dependency Installer"
if $IS_TERMUX; then
    info "Environment : Termux (Android)"
elif $IS_LINUX; then
    info "Environment : Linux"
elif $IS_MACOS; then
    info "Environment : macOS (Darwin)"
else
    info "Environment : Unknown ($OS)"
fi
info "Architecture: $ARCH"

# ─────────────────────────────────────────────────────────────────────────────
#  Shared helper: add a line to shell rc files if not already present
#  FIX: Covers ~/.bashrc, ~/.zshrc, and ~/.profile for both bash and zsh users
# ─────────────────────────────────────────────────────────────────────────────
_persist_line() {
    local line="$1"
    local targets=("$HOME/.bashrc" "$HOME/.profile")
    # Also update .zshrc if it exists or if the user's shell is zsh
    if [ -f "$HOME/.zshrc" ] || [ "${SHELL:-}" = "$(command -v zsh 2>/dev/null)" ]; then
        targets+=("$HOME/.zshrc")
    fi
    for rc in "${targets[@]}"; do
        if [ -f "$rc" ] || [ "$rc" = "$HOME/.profile" ]; then
            grep -qxF "$line" "$rc" 2>/dev/null \
                || echo "$line" >> "$rc"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
#  TERMUX
# ─────────────────────────────────────────────────────────────────────────────
install_termux() {
    head_ "Termux: Updating packages"
    pkg update -y && pkg upgrade -y

    head_ "Termux: Core packages"
    # Try openjdk versions in order (package name varies by Termux repo state)
    pkg install -y openjdk-21 2>/dev/null \
    || pkg install -y openjdk-17 2>/dev/null \
    || {
        warn "openjdk-21/17 not found via pkg – trying termux-apt-repo..."
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

    # FIX: Export JAVA_HOME so apktool can find the JVM in Termux
    JAVA_HOME_CANDIDATE="$(find /data/data/com.termux/files/usr -name 'java' -type f 2>/dev/null | head -1 | xargs -I{} dirname {} | xargs -I{} dirname {} 2>/dev/null)" || true
    if [ -n "$JAVA_HOME_CANDIDATE" ] && [ -d "$JAVA_HOME_CANDIDATE" ]; then
        export JAVA_HOME="$JAVA_HOME_CANDIDATE"
        _persist_line "export JAVA_HOME=\"$JAVA_HOME_CANDIDATE\""
        ok "JAVA_HOME set to $JAVA_HOME_CANDIDATE"
    fi

    head_ "Termux: Python base"
    pip install --upgrade pip setuptools wheel || true

    # ── Androguard ─────────────────────────────────────────────────────────────
    head_ "Termux: androguard 3.3.5 (lightweight, Termux-compatible)"

    pip install --upgrade \
        "networkx>=2.6,<3.2" \
        "colorama>=0.4" \
        "future>=0.18" \
        "pyelftools>=0.29" \
        "pycryptodome>=3.15" \
        "loguru" "pyyaml" "click" "asn1crypto" \
    || true

    pip install "androguard==3.3.5" 2>/dev/null \
    || {
        warn "3.3.5 not available – installing latest with constrained deps..."
        pip install androguard --no-deps \
        && pip install \
            "networkx>=2.6,<3.2" lxml "pycryptodome>=3.15" \
            loguru pyyaml click asn1crypto apkInspector mutf8 \
        || pip install androguard --no-build-isolation \
        || err "androguard install failed. See TROUBLESHOOTING below."
    }

    # ── Frida ──────────────────────────────────────────────────────────────────
    head_ "Termux: frida (pre-built wheel)"

    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")

    # 1. Try pkg frida (fastest, pre-compiled for Termux)
    if pkg install -y python-frida 2>/dev/null; then
        ok "frida installed via pkg (python-frida)"
    else
        INSTALLED_FRIDA=false

        # 2. Try multiple frida releases – newest stable first with ARM64 wheels
        for FRIDA_VER in "16.2.1" "16.1.11" "16.0.19"; do
            WHEEL_OLD="frida-${FRIDA_VER}-cp${PY_VER}-cp${PY_VER}-android-arm64.whl"
            WHEEL_NEW="frida-${FRIDA_VER}-cp${PY_VER}-cp${PY_VER}-linux_aarch64.whl"
            BASE_URL="https://github.com/frida/frida/releases/download/${FRIDA_VER}"

            for WHEEL in "$WHEEL_OLD" "$WHEEL_NEW"; do
                info "Trying frida wheel: $WHEEL"
                if curl -fL "${BASE_URL}/${WHEEL}" -o "/tmp/${WHEEL}" 2>/dev/null; then
                    pip install "/tmp/${WHEEL}" 2>/dev/null \
                        && { ok "frida installed: $WHEEL"; INSTALLED_FRIDA=true; break 2; }
                fi
            done
        done

        # 3. Try pip with --only-binary (won't build from source)
        if ! $INSTALLED_FRIDA; then
            warn "Pre-built frida wheels not found. Trying pip --only-binary..."
            pip install frida --only-binary :all: 2>/dev/null \
            && { ok "frida installed via pip binary."; INSTALLED_FRIDA=true; } \
            || warn "frida not installed – unguard.py works without it."
        fi

        if $INSTALLED_FRIDA; then
            pip install frida-tools --only-binary :all: 2>/dev/null \
                || warn "frida-tools not installed (optional)."
        fi
    fi

    # ── apktool ────────────────────────────────────────────────────────────────
    head_ "Termux: apktool"
    LBIN="$HOME/.local/bin"
    mkdir -p "$LBIN"
    if ! command -v apktool &>/dev/null && [ ! -f "$LBIN/apktool.jar" ]; then
        VER="2.9.3"
        BASE="https://github.com/iBotPeaches/Apktool/releases/download/v${VER}"
        RAW="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux"
        info "Downloading apktool ${VER}..."
        curl -fL "${BASE}/apktool_${VER}.jar" -o "${LBIN}/apktool.jar" \
            || { err "apktool download failed. Check network or download manually."; }
        curl -fL "${RAW}/apktool" -o "${LBIN}/apktool" \
            || { err "apktool wrapper script download failed."; }
        chmod +x "${LBIN}/apktool"
        ok "apktool installed at ${LBIN}/apktool"
        # Add to PATH for current session
        export PATH="$PATH:$LBIN"
        # FIX: persist across all shell configs
        _persist_line "export PATH=\"\$PATH:\$HOME/.local/bin\""
    else
        ok "apktool already present."
    fi

    # ── Signing tools ──────────────────────────────────────────────────────────
    head_ "Termux: signing tools"
    pkg install -y apksigner aapt2 android-tools 2>/dev/null || true

    pip install colorama --upgrade 2>/dev/null || true

    ok "Termux setup complete!"
    _summary
}

# ─────────────────────────────────────────────────────────────────────────────
#  LINUX  (Debian/Ubuntu/Fedora/Arch)
# ─────────────────────────────────────────────────────────────────────────────
install_linux() {
    head_ "Linux: System packages"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            python3 python3-pip python3-venv python3-dev python3-lxml \
            openjdk-17-jre-headless \
            build-essential libffi-dev libssl-dev libxml2-dev libxslt-dev \
            wget curl unzip zip git \
            zipalign || true
        # apksigner – try from android-sdk-build-tools if available, else standalone
        sudo apt-get install -y apksigner 2>/dev/null || true

    elif command -v dnf &>/dev/null; then
        sudo dnf install -y \
            python3 python3-pip python3-lxml python3-devel \
            java-17-openjdk-headless gcc make \
            libffi-devel openssl-devel libxml2-devel libxslt-devel \
            wget curl unzip zip git || true

    elif command -v pacman &>/dev/null; then
        sudo pacman -Syu --noconfirm \
            python python-pip python-lxml \
            jdk17-openjdk base-devel libffi openssl \
            wget curl unzip zip git || true
    fi

    head_ "Linux: Python packages"
    # FIX: Use pip3 consistently on Linux to avoid python2/python3 ambiguity
    pip3 install --upgrade pip setuptools wheel || true
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

    head_ "Linux: apktool"
    if ! command -v apktool &>/dev/null; then
        VER="2.9.3"
        sudo curl -fL \
            "https://github.com/iBotPeaches/Apktool/releases/download/v${VER}/apktool_${VER}.jar" \
            -o /usr/local/bin/apktool.jar \
            || { err "apktool JAR download failed."; }
        sudo curl -fL \
            "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
            -o /usr/local/bin/apktool \
            || { err "apktool wrapper download failed."; }
        sudo chmod +x /usr/local/bin/apktool
        ok "apktool installed."
    else
        ok "apktool already present."
    fi

    # FIX: attempt apksigner install via Android build-tools cmdline-tools if not packaged
    if ! command -v apksigner &>/dev/null; then
        warn "apksigner not found via package manager."
        warn "To install: download Android build-tools from developer.android.com/studio"
        warn "Or: pip3 install apkutils2 (provides limited signing support)"
        warn "Fallback: jarsigner (from JDK) will be used automatically."
    fi

    ok "Linux setup complete!"
    _summary
}

# ─────────────────────────────────────────────────────────────────────────────
#  macOS (Homebrew)
#  FIX: New macOS/Darwin install path – was completely missing in v1.x
# ─────────────────────────────────────────────────────────────────────────────
install_macos() {
    head_ "macOS: Checking Homebrew"
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
            || { err "Homebrew install failed. Install manually: https://brew.sh"; exit 1; }
        # Add brew to PATH for Apple Silicon
        if [ -d "/opt/homebrew/bin" ]; then
            export PATH="/opt/homebrew/bin:$PATH"
            _persist_line 'export PATH="/opt/homebrew/bin:$PATH"'
        fi
    fi
    ok "Homebrew present."

    head_ "macOS: System packages"
    brew install python3 openjdk@17 git curl wget unzip || true
    # Link OpenJDK for system use
    sudo ln -sfn "$(brew --prefix openjdk@17)/libexec/openjdk.jdk" \
        /Library/Java/JavaVirtualMachines/openjdk-17.jdk 2>/dev/null || true
    export JAVA_HOME="$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home"
    _persist_line "export JAVA_HOME=\"$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home\""

    head_ "macOS: Python packages"
    pip3 install --upgrade pip setuptools wheel || true
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

    head_ "macOS: apktool"
    if command -v brew &>/dev/null && brew list apktool &>/dev/null 2>&1; then
        ok "apktool already installed via Homebrew."
    elif ! command -v apktool &>/dev/null; then
        # Try Homebrew first
        brew install apktool 2>/dev/null && ok "apktool installed via Homebrew." \
        || {
            warn "apktool not in Homebrew – downloading JAR manually..."
            VER="2.9.3"
            mkdir -p "$HOME/.local/bin"
            curl -fL \
                "https://github.com/iBotPeaches/Apktool/releases/download/v${VER}/apktool_${VER}.jar" \
                -o "$HOME/.local/bin/apktool.jar" || true
            curl -fL \
                "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
                -o "$HOME/.local/bin/apktool" || true
            chmod +x "$HOME/.local/bin/apktool"
            export PATH="$PATH:$HOME/.local/bin"
            _persist_line 'export PATH="$PATH:$HOME/.local/bin"'
            ok "apktool installed to ~/.local/bin"
        }
    else
        ok "apktool already present."
    fi

    # apksigner: available via Android SDK or as standalone
    if ! command -v apksigner &>/dev/null; then
        warn "apksigner not found."
        warn "Install Android build-tools: brew install --cask android-commandlinetools"
        warn "Or use Android Studio SDK Manager to install build-tools."
        warn "Fallback: jarsigner (from JDK) will be used automatically."
    fi

    ok "macOS setup complete!"
    _summary
}

# ─────────────────────────────────────────────────────────────────────────────
#  Summary / Verification
#  FIX: References updated from Ana.py → unguard.py
# ─────────────────────────────────────────────────────────────────────────────
_summary() {
    head_ "Verification"

    python3 -c "import androguard; print('androguard', androguard.__version__)" 2>/dev/null \
        && ok "androguard OK" || err "androguard MISSING"

    python3 -c "import frida; print('frida', frida.__version__)" 2>/dev/null \
        && ok "frida OK" || warn "frida missing (optional)"

    java -version 2>&1 | head -1 | grep -q "version" \
        && ok "java OK" || err "java MISSING (required for apktool)"

    { command -v apktool &>/dev/null || [ -f "$HOME/.local/bin/apktool.jar" ]; } \
        && ok "apktool OK" || err "apktool MISSING"

    command -v apksigner &>/dev/null && ok "apksigner OK" \
        || warn "apksigner missing (fallback: jarsigner – SHA256withRSA)"
    command -v zipalign  &>/dev/null && ok "zipalign OK"  \
        || warn "zipalign missing (optional)"
    command -v jarsigner &>/dev/null && ok "jarsigner OK (JDK present)" \
        || warn "jarsigner missing (install JDK)"

    head_ "Quick Start"
    echo -e "  ${BOLD}python3 unguard.py app.apk --patch all${RESET}                # full auto"
    echo -e "  ${BOLD}python3 unguard.py app.apk --detect-only${RESET}              # scan only"
    echo -e "  ${BOLD}python3 unguard.py app.apk --patch iap,ads${RESET}            # specific categories"
    echo -e "  ${BOLD}python3 unguard.py app.apk --patch all --no-sign${RESET}      # unsigned output"
    echo -e "  ${BOLD}python3 unguard.py app.apk --patch all --report r.json${RESET} # JSON report"
    echo -e "  ${BOLD}python3 unguard.py --smali-file Pay.smali --patch iap${RESET} # smali-only mode"

    head_ "Troubleshooting"
    cat <<'HELP'

JAVA
----
 "Unable to locate package openjdk-17":
   pkg install openjdk-21         # Termux now ships 21, not 17
   # If that also fails:
   pkg update && pkg upgrade && pkg install openjdk-21

 OutOfMemoryError when running apktool:
   export JAVA_OPTS="-Xmx2g"
   # Add this to ~/.bashrc or ~/.zshrc to make it permanent

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
 No matching wheel (Termux):
   Go to https://github.com/frida/frida/releases
   Download: frida-<ver>-cp<pyver>-cp<pyver>-android-arm64.whl
   Install:  pip install frida-*.whl

 frida-server version mismatch:
   frida wheel version must EXACTLY match frida-server running on device

 Build from source hangs (never do this on Termux):
   Always use --only-binary :all: or a pre-built wheel

APKTOOL
-------
 Resource decode errors (brut.androlib):
   unguard.py auto-retries with --no-res flag

 Manual version override:
   APKTOOL_JAR=/path/to/apktool.jar python3 unguard.py app.apk --patch all

SIGNING
-------
 Keystore not found (auto-generated by unguard.py, or manually):
   keytool -genkey -v -keystore my.keystore -alias mykey \
           -keyalg RSA -keysize 2048 -validity 10000

 apksigner not available:
   unguard.py falls back to jarsigner with SHA256withRSA automatically.
   Devices running Android 11+ may warn about v1-only signed APKs;
   install Android build-tools and put apksigner on PATH for v2/v3 signatures.

 No-sign mode (install via ADB + MITM proxy):
   python3 unguard.py app.apk --patch all --no-sign

MEMORY / CACHE
--------------
 Large APKs hitting memory limits (default 512 MB cache):
   CACHE_MAX_MB=256 python3 unguard.py app.apk --patch all

 Increase for apps with 50k+ smali files:
   CACHE_MAX_MB=1024 python3 unguard.py app.apk --patch all

GENERAL
-------
 Debug mode (keep workspace):
   python3 unguard.py app.apk --patch all --keep-work 2>&1 | tee ug.log

 JSON patch report:
   python3 unguard.py app.apk --patch all --report patch_report.json

 Re-run installer:
   bash installer.sh
HELP
}

# ─────────────────────────────────────────────────────────────────────────────
#  Dispatch
# ─────────────────────────────────────────────────────────────────────────────
if $IS_TERMUX; then
    install_termux
elif $IS_LINUX; then
    install_linux
elif $IS_MACOS; then
    install_macos
else
    warn "Unknown OS ($OS) – attempting generic pip install..."
    pip3 install \
        androguard frida frida-tools colorama lxml networkx \
        pyelftools pycryptodome loguru pyyaml click asn1crypto \
    || pip install \
        androguard frida frida-tools colorama lxml networkx \
        pyelftools pycryptodome loguru pyyaml click asn1crypto \
    || err "pip install failed on unknown OS."
    _summary
fi
