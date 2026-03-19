# 🔓 UnGuard v3.3.1

**Hybrid Static + Runtime Android APK Analysis & Patching Framework**

![version](https://img.shields.io/badge/version-3.3.1-blue)
![python](https://img.shields.io/badge/python-3.9%2B-green)
![platform](https://img.shields.io/badge/platform-Android-orange)
![status](https://img.shields.io/badge/status-active-success)
![license](https://img.shields.io/badge/license-educational-lightgrey)

------------------------------------------------------------------------

## 🚀 Overview

**UnGuard** is a reverse-engineering toolkit to **analyze, patch,
rebuild, and sign APKs**.

It combines: - Static analysis (smali + AST) - Runtime interception
(TLS + fake verification) - Automated patching

------------------------------------------------------------------------

## 🧠 Architecture

    APK → Decode → Smali Cache → AST Parser → Patch Engine → Rebuild → Sign

------------------------------------------------------------------------

## ⭐ Features

### 🔍 Detection

-   Multi-threaded scanning
-   Detects IAP, Ads, Integrity, Server logic

### 🧬 Smali AST Parser

-   Structure-aware parsing
-   Prevents false matches

### 🧠 Patch Categories

  Flag        Description
  ----------- ----------------
 - integrity         Unlock premium
 - integrity   Disable checks
 - ads         Remove ads
 - storageIO   Force flags
 - serverIO    Fake responses
 - all         Everything

------------------------------------------------------------------------

## 🌐 Runtime Features

### `--fake-google-verify`

-   Fakes Google validation
-   Returns success

### `--tls-intercept`

-   Intercepts HTTPS traffic

------------------------------------------------------------------------

## ⚡ Performance

-   Multi-threading
-   Smart caching
-   Parallel scanning

------------------------------------------------------------------------

## 🧾 Patch Report

``` json
{
  "tool": "UnGuard",
  "version": "3.3.1",
  "total_patches": 120
}
```

------------------------------------------------------------------------

## 🛠️ Installation

### Requirements

-   Python 3.9+
-   Java
-   apktool
-   zipalign
-   apksigner

------------------------------------------------------------------------

## ⚙️ Usage

### Basic

``` bash
python unguard.py app.apk --patch all
```

### With fake verification

``` bash
python unguard.py app.apk --patch iap --fake-google-verify
```

### Full mode

``` bash
python unguard.py app.apk \
  --patch all \
  --fake-google-verify \
  --tls-intercept
```

------------------------------------------------------------------------

## 📟 CLI Help

    --patch <category>
    --fake-google-verify
    --tls-intercept
    --workers <n>

------------------------------------------------------------------------

## 🖥️ Example Output

    [+] IAP files : 36
    [*] Fake Google verification enabled
    [✓] SUCCESS
    [✓] Output: app_patched.apk

------------------------------------------------------------------------

## 🎮 Supported Frameworks

-   Unity
-   Unreal
-   Flutter
-   React Native

------------------------------------------------------------------------

## 🔐 Obfuscation Support

-   DexGuard
-   Arxan
-   DashO

------------------------------------------------------------------------

## ⚠️ Disclaimer

Educational use only.

------------------------------------------------------------------------

## ⭐ Tip

Use:

    --patch all --fake-google-verify --tls-intercept

for best results.allllll
