# 🛡️ UnGuard v1.0.0

**Android APK Patcher** – Detect · Deobfuscate · Patch · Rebuild · Sign

A comprehensive Python utility for analyzing and patching Android applications across multiple frameworks, obfuscation layers, and security mechanisms.

---

## ✨ Features

### Patch Categories
- **🏪 IAP** – Google Play, Amazon, Huawei in-app purchasing & premium gates
- **🔐 Integrity** – Play Integrity, SafetyNet, LVL, signature verification checks
- **📢 Ads** – AdMob, Facebook Ads, Unity Ads, AppLovin, IronSource, MoPub, and 10+ more
- **💾 Storage I/O** – SQLite, Room, SharedPreferences premium flags
- **🌐 Server I/O** – JSON, Retrofit2, OkHttp response code spoofing

### Framework Support
✅ Unity (IL2CPP & Mono)  
✅ Unreal Engine  
✅ Flutter / Dart  
✅ React Native  
✅ Xamarin / .NET  
✅ Cocos2d-x  
✅ libGDX  
✅ Godot  
✅ Native Java  

### Obfuscation Handling
**Commercial:**
- DexGuard, Arxan, DashO, AppSealing, Bangcle, 360Jiagu, LIAPP, Tencent

**Custom:**
- XOR/AES string encryption
- String array tables
- StringBuilder chains
- Opaque predicates
- Dead code & goto chains
- DexClassLoader packers
- Native JNI stubs
- Reflection hiding

### Advanced Capabilities
- 🔄 Multi-threaded pattern scanning & patching
- 📦 Auto-detection of framework/engine
- 🎯 Commercial obfuscation fingerprinting
- 🔓 Custom deobfuscation transforms
- ✂️ Split APK handling (AAB → APK conversion)
- 🖊️ APK signing (automatic debug keystore generation)
- 📊 Detailed analysis reports

---

## 🚀 Quick Start

### Installation

bash
# Clone or download UnGuard
git clone https://github.com/ABDO10DZ/unguard.git
cd unguard

# Run the installer script (Linux/macOS/WSL)
bash installer.sh

# Or install dependencies manually
pip install colorama androguard


### APK Mode

bash
# Patch IAP + Integrity checks
python unguard.py app.apk --patch iap,integrity

# Patch everything
python unguard.py app.apk --patch all

# Analyze only (no build)
python unguard.py app.apk --detect-only

# Custom output directory
python unguard.py app.apk --patch iap,ads -o ./output

# No signing
python unguard.py app.apk --patch all --no-sign


### Smali File Mode

Patch individual .smali files without needing apktool:

bash
# Single file
python unguard.py --smali-file BillingManager.smali --patch iap

# Multiple files
python unguard.py --smali-file A.smali,B.smali --patch ads,iap

# Glob patterns
python unguard.py --smali-file smali/*.smali --patch all

# Output to directory
python unguard.py --smali-file Pay.smali --patch iap -o ./patched


---

## 📋 Patch Categories

| Category | Description | Targets |
|----------|-------------|---------|
| iap | In-app purchasing bypass | BillingClient, Amazon IAP, Huawei IAP, premium gates |
| integrity | Integrity verification bypass | Play Integrity, SafetyNet, LVL, signature checks |
| ads | Ad SDK removal | 15+ ad networks including AdMob, Facebook, Unity Ads |
| storageIO | Premium flag overrides | SQLite, Room, SharedPreferences |
| serverIO | Server response spoofing | JSON parsing, Retrofit2, OkHttp, HTTP codes |
| all | All patches in one build | Everything above |

**Combine multiple patches:**
bash
--patch iap,integrity,ads
--patch iap|ads|storageIO
--patch all


---

## 🔧 Environment Variables & Flags

### Tool Paths
bash
export APKTOOL_JAR=/path/to/apktool.jar
export KEYSTORE=/path/to/keystore.jks
export KEY_ALIAS=myalias
export KEY_PASS=mypass
export ZIPALIGN=/usr/bin/zipalign
export APKSIGNER=/path/to/apksigner
export BUNDLETOOL=/path/to/bundletool.jar
export MAX_WORKERS=8


### CLI Flags
bash
--work-dir DIR              Override temp workspace
--no-sign                   Output unsigned APK
--no-deob                   Skip deobfuscation pass
--keep-work                 Keep temp files after build
--detect-only               Analyze without patching
--workers N                 Thread count (default: CPU cores)


---

## 📊 Detection & Analysis

UnGuard performs comprehensive static analysis:

1. **Framework Detection** – Identifies game engines, frameworks
2. **Commercial Obfuscation** – Detects DexGuard, Arxan, and others
3. **Custom Obfuscation** – Identifies string encryption, packers
4. **API Pattern Scanning** – Finds protection mechanisms
5. **Deobfuscation** – Annotates and simplifies obfuscated code
6. **Patching** – Applies targeted fixes for detected protections

Output includes:
- Detection scores (0-100 per category)
- File-level findings
- Patch application counts
- Deobfuscation transforms applied

---

## 💻 Architecture

### Core Components

**SmaliCache**
- Single-pass sequential I/O of all smali files
- Shared across all scanning engines
- Memory-efficient for large APKs

**Pattern Scanning**
- Multi-threaded regex-based detection
- 60+ detection patterns across 5 categories
- Intelligent windowing & method-body analysis

**Patch Engine**
- Category-specific patchers (IAP, Integrity, Ads, Storage, Server)
- Smali bytecode manipulation
- Register management & locals insertion
- Method body replacement with valid bytecode

**Obfuscation Engines**
- Custom deobfuscator (XOR, AES, reflection, etc.)
- Commercial fingerprint detection
- Transform annotations in patched output

**Framework Detector**
- Two-pass detection (ZIP + decompiled)
- Handles split APKs seamlessly
- Disambiguates Unity Mono vs IL2CPP

---

## 📁 File Structure

unguard/
├── unguard.py              # Main patcher (2700+ LOC)
├── installer.sh            # Dependency installer
└── README.md              # This file


---

## ⚙️ Requirements

### System
- Python 3.9+
- Java 11+ (for apktool)
- keytool (JDK)

### Python Dependencies
- colorama – Terminal colors
- androguard – Optional (APK analysis)

### External Tools
- apktool.jar – APK decompilation/rebuilding
- zipalign – APK alignment
- apksigner or jarsigner – APK signing
- bundletool.jar – AAB handling (optional)

---

## 🎯 Usage Examples

### Detect All Protections (No Patching)
bash
python unguard.py target.apk --detect-only


### Bypass IAP Only
bash
python unguard.py myapp.apk --patch iap -o ./patched


### Full Bypass (All Protection)
bash
python unguard.py myapp.apk --patch all --output ./build


### Handle Android App Bundle
bash
python unguard.py app.aab --patch all --bundletool /path/to/bundletool.jar


### Patch Extracted Smali Files
bash
python unguard.py --smali-file decompiled/smali/com/example/Billing.smali \
                  --patch iap,integrity -o ./output


### Batch Process Multiple Files
bash
python unguard.py --smali-file "extracted/**/*.smali" --patch ads


---

## 📈 Performance

- **Single-threaded decompilation:** ~10-30s (apktool)
- **Multi-threaded pattern scan:** ~1-5s (1000+ smali files)
- **Patching:** ~2-10s (variable by patch count)
- **Rebuilding:** ~30-60s (apktool rebuild)
- **Signing:** ~5-10s

**Total time:** 2-3 minutes per APK (varies by size & obfuscation)

---

## 🔐 Security Notes

- ⚠️ **Educational Use Only** – For authorized testing and reverse engineering
- Creates a debug keystore automatically if none exists
- Preserves original APK structure when possible
- All operations logged with timestamps

---

## 📝 Output Files

- app_iap.apk – IAP patches applied
- app_all.apk – All patches applied
- *_patched.smali – Patched smali files (smali mode)

---

## 🛠️ Troubleshooting

### apktool.jar not found
bash
export APKTOOL_JAR=/path/to/apktool.jar


### keytool not found
Ensure JDK is installed and in PATH:
bash
which keytool  # Check if available


### Decompilation Timeout
Increase timeout or use --no-res:
bash
python unguard.py app.apk --patch all --work-dir /tmp


### Memory Issues with Large APKs
Reduce MAX_WORKERS:
MAX_WORKERS=2 python unguard.py app.apk --patch all

---

## 📚 Advanced Usage

### Custom Tool Paths
bash
python unguard.py app.apk --patch all \
  --apktool /opt/tools/apktool.jar \
  --keystore /opt/certs/my.jks \
  --alias mykey \
  --password mypass


### Preserve Work Directory (Debugging)
bash
python unguard.py app.apk --patch iap --keep-work
# /tmp/anapatch_XXXX/ will not be deleted

---

## 📊 Detection Example Output

```
────────────────────────────────────────────────────────────
  Framework Detection Result
────────────────────────────────────────────────────────────
  Unity (IL2CPP)  [libil2cpp.so]
  Strategy: IL2CPP compiles C# to native ARM – game logic not smali-patchable.
            IAP/Integrity Java wrappers (com.unity3d.*) ARE patchable.

────────────────────────────────────────────────────────────
  Commercial Obfuscation Detection
────────────────────────────────────────────────────────────
  DEXGUARD  (5 hit(s))
  Commercial obfuscation score: 35/100

────────────────────────────────────────────────────────────
  API Detection
────────────────────────────────────────────────────────────
  IAP files       : 12
  Integrity files : 8
  Ads files       : 15
  Storage files   : 3
  Server-reply    : 6
```

---

## 🤝 Contributing

Improvements welcome! Areas for contribution:
- Additional framework detection signatures
- New obfuscation deobfuscators
- Patch pattern enhancements
- Documentation & examples

---

## 📄 License

Educational & research use. Check local laws regarding reverse engineering.

---

## 🙏 Credits

**UnGuard v1.0.0** – Comprehensive Android APK Analysis & Patching

Built with focus on:
- ✨ Pattern detection accuracy
- 🚀 Performance & scalability
- 🎯 Framework compatibility
- 🔧 Maintainability

---

## 📞 Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check the troubleshooting section above
- Verify all external tools are properly installed

---

**Happy patching! 🛡️**