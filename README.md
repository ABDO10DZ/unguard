# UnGuard v3.0.0

**Hybrid Static + Runtime Android APK Analysis & Patching Framework**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Author](https://img.shields.io/badge/author-0xbytecode-purple.svg)](https://github.com/0xbytecode)
[![Tool](https://img.shields.io/badge/tool-unguard-blue.svg)]()
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)]()

UnGuard is a powerful, all‑in‑one tool for Android security testing and educational bypass of in‑app purchases, integrity checks, ads, and more. It combines static analysis (smali patching) with optional runtime instrumentation to observe and learn from app behaviour, then apply that knowledge as additional static patches – all without needing a rooted device or Frida.

---

## ✨ Features

- **Multi‑category patching**
  - `iap`        – Google Play / Amazon / Huawei IAP, premium gates
  - `integrity`  – Play Integrity, SafetyNet, LVL, signature checks
  - `ads`        – AdMob, Facebook, Unity, AppLovin, IronSource, MoPub, Vungle, InMobi, Chartboost, Tapjoy, Pangle
  - `storageIO`  – SQLite / Room / SharedPreferences premium flags
  - `serverIO`   – JSON / Retrofit / OkHttp server‑reply status codes
  - `all`        – Everything above in one build

- **Framework detection** – automatically detects Unity (Mono/IL2CPP), Unreal, Flutter, React Native, Xamarin, Cocos2d‑x, libGDX, Godot, and more.

- **Obfuscation handling**
  - Commercial: DexGuard, Arxan, DashO, AppSealing, Bangcle, 360 Jiagu, LIAPP
  - Custom: XOR/AES encrypted strings, string‑arrays, StringBuilder chains, opaque predicates, dead‑goto chains, DexClassLoader packers, reflection hiding
  - Active deobfuscation that removes/annotates obfuscated constructs

- **Runtime instrumentation (optional)**
  - Inject a lightweight bridge into the APK that streams lifecycle, network, storage, and exception events live to your console
  - `--trace-runtime` – hook Activity/Fragment lifecycle and sensitive methods
  - `--net-debug`     – intercept OkHttp traffic (URL, method, status) without any proxy
  - `--tls-intercept` – inject a network security config that trusts user CAs (enables mitmproxy / Burp)
  - `--learn`         – record all observed events into a SQLite profile; automatically discover premium‑gate endpoints
  - `--hybrid`        – convert learned rules into additional static patches (no‑root, no‑proxy)

- **Smali file mode** – patch individual `.smali` files directly (no APK / apktool needed)

- **Parallel processing** – multi‑threaded scanning and patching for speed

- **Structured JSON report** – export all applied patches and statistics

- **Atomic writes** – never corrupt a file even if interrupted

- **Auto‑signing** – generates a debug keystore if none provided; supports apksigner and jarsigner fallback

---

## 📦 Requirements

- **Python 3.9+**
- **Java** (for apktool and bundletool)
- **apktool.jar** – [download](https://bitbucket.org/iBotPeaches/apktool/downloads/)
- **Optional** – `androguard` (for extra metadata): `pip install androguard`
- **Optional** – `bundletool.jar` (for AAB/APKS extraction): [download](https://github.com/google/bundletool/releases)

All other Python dependencies are built‑in or installed automatically if needed.

---

## 🚀 Installation

1. **Clone or download** this repository (save `unguard.py` to your machine).
2. **Place `apktool.jar`** in the same directory or set the environment variable `APKTOOL_JAR`.
3. (Optional) **Install androguard** for richer metadata:
    ```bash
    pip install androguard
    ```
4. Make sure `java` is in your PATH.

That’s it – no additional Python packages are required for basic operation.

---

## 🛠️ Usage

UnGuard can operate in two modes: **APK mode** (full analysis + patching) and **Smali file mode** (quick patching of individual `.smali` files).

### APK mode – patch a whole application

```bash
python unguard.py your_app.apk --patch iap,integrity
```

This will:
- Decompile the APK (using apktool)
- Detect all relevant IAP and integrity checks
- Apply bypass patches
- Rebuild and sign the APK (creating a debug keystore if needed)
- Output `your_app_iap_integrity.apk`

### Smali file mode – patch one or more smali files directly

```bash
python unguard.py --smali-file BillingManager.smali --patch iap
```

You can specify multiple files with commas or glob patterns:
```bash
python unguard.py --smali-file "smali/*.smali" --patch all
```

### Patch categories

| Category    | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `iap`       | Google Play / Amazon / Huawei IAP, premium boolean gates                    |
| `integrity` | Play Integrity, SafetyNet, LVL, signature checks, root/detect               |
| `ads`       | AdMob, Facebook, Unity Ads, AppLovin, IronSource, MoPub, Vungle, InMobi …  |
| `storageIO` | SQLite / Room / SharedPreferences reads that gate premium features          |
| `serverIO`  | JSON status codes, Retrofit/OkHttp response checks                          |
| `all`       | All of the above                                                            |

Combine categories with commas, pipes, or spaces:
```bash
--patch iap,integrity,ads
--patch "iap|ads|storageIO"
```

### Runtime instrumentation flags (optional)

Add these to activate live analysis:

| Flag                 | Description                                                                                        |
|----------------------|----------------------------------------------------------------------------------------------------|
| `--trace-runtime`    | Inject hooks into Activity/Fragment lifecycle and sensitive methods (e.g. `isPremium`). Events stream live. |
| `--net-debug`        | Intercept all OkHttp requests/responses (URL, method, status) – no proxy needed.                  |
| `--tls-intercept`    | Inject network security config that trusts user CAs. Use with mitmproxy / Burp on `--proxy-port`. |
| `--learn`            | Record all observed events into `--profile-db` and auto‑discover premium endpoints.                |
| `--hybrid`           | Apply rules from a previous `--learn` session as additional static patches.                        |
| `--bridge-port`      | TCP port for the APK→UnGuard event bridge (default 17185). Forward it with `adb forward`.          |
| `--proxy-port`       | Local port for MITM proxy (default 8080).                                                          |
| `--profile-db`       | SQLite database file for learned behaviour (default `unguard_profile.db`).                         |
| `--rules-file`       | JSON file for learned rules (default `unguard_rules.json`).                                        |

### Complete examples

- **Basic IAP + Integrity patch**  
    ```bash
    python unguard.py game.apk --patch iap,integrity
    ```

- **Patch everything, trace runtime, intercept TLS**  
    ```bash
    python unguard.py game.apk --patch all --trace-runtime --tls-intercept
    ```

- **Learn mode – record behaviour and generate rules**  
    ```bash
    python unguard.py game.apk --patch all --learn
    # interact with the app, then press Ctrl+C
    ```

- **Hybrid mode – apply learned rules as static patches**  
    ```bash
    python unguard.py game.apk --patch all --hybrid
    ```

- **Smali file mode with output directory**  
    ```bash
    python unguard.py --smali-file Billing.smali --patch iap -o ./patched_smali
    ```

---

## ⚙️ Configuration

You can customise tool paths and behaviour via environment variables or command‑line arguments.

| Environment | CLI equivalent | Purpose                          |
|-------------|----------------|----------------------------------|
| `APKTOOL_JAR` | `--apktool`    | Path to `apktool.jar`            |
| `KEYSTORE`    | `--keystore`   | Keystore file for signing        |
| `KEY_ALIAS`   | `--alias`      | Key alias                        |
| `KEY_PASS`    | `--password`   | Keystore password                |
| `BUNDLETOOL`  | `--bundletool` | Path to `bundletool.jar`         |
| `ZIPALIGN`    | (no CLI)       | Path to `zipalign`               |
| `APKSIGNER`   | (no CLI)       | Path to `apksigner`              |
| `MAX_WORKERS` | `--workers`    | Number of parallel threads       |
| `CACHE_MAX_MB`| (no CLI)       | Smali cache size (MB)             |

If a keystore is not found, UnGuard automatically generates a debug one.

---

## 📂 Output

- **Patched APK** – named `{original_name}_{category_slug}.apk` (e.g., `game_iap_integrity.apk`).
- **Unsigned intermediate** – kept in the work directory if `--no-sign` is used.
- **HTML / JSON report** – if `--report report.json` is given, a structured list of all patches is saved.
- **Runtime profile** – when using `--learn`, `unguard_profile.db` and `unguard_rules.json` are created.

---

## 📝 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

**Disclaimer**: This tool is intended for educational purposes and security testing on applications you own or have explicit permission to analyse. Misuse for illegal purposes is strictly prohibited.

---

## 🙏 Acknowledgments

- [apktool](https://ibotpeaches.github.io/Apktool/) – for reliable APK decompilation/rebuilding
- [androguard](https://github.com/androguard/androguard) – for static analysis (optional)
- [Google bundletool](https://github.com/google/bundletool) – for AAB/APKS handling
- The open‑source reversing community for inspiration and techniques

---

*UnGuard v3.0.0 – because sometimes you need to see what the app really does.*
