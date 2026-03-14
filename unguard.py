#!/usr/bin/env python3
# unguard.py
"""
UnGuard v1.0.0 – Android APK Patcher
========================
Detect · Deobfuscate · Patch · Rebuild · Sign

Patch categories (combine freely with --patch):
  iap        : Google Play / Amazon / Huawei IAP · premium gates
  integrity  : Play Integrity · SafetyNet · LVL · signature checks
  ads        : AdMob · Facebook · Unity Ads · AppLovin · IronSource · MoPub
               Vungle · InMobi · Chartboost · Tapjoy · Pangle
  storageIO  : SQLite / Room / SharedPreferences premium flags
  serverIO   : JSON / Retrofit / OkHttp server-reply status codes
  all        : Everything above in one build

Framework support:
  Unity IL2CPP · Unity Mono · Unreal · Flutter · React Native
  Xamarin · Cocos2d-x · libGDX · Godot · Native Java

Obfuscation support:
  Commercial : DexGuard · Arxan · DashO · AppSealing · Bangcle · 360Jiagu · LIAPP
  Custom     : XOR/AES strings · String-arrays · StringBuilder chains
               Opaque predicates · Dead-goto chains · DexClassLoader packers
               Native JNI stubs · Reflection hiding
"""

from __future__ import annotations

import os, sys, re, shutil, zipfile, tempfile, threading, time, subprocess, argparse
from enum            import Enum, auto
from pathlib         import Path
from collections     import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────────────────────────────────────
#  Colours (ANSI fallback; no colorama required)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from colorama import init as _ci, Fore, Style
    _ci(autoreset=True)
    class C:
        R=Fore.RED; G=Fore.GREEN; Y=Fore.YELLOW; B=Fore.BLUE
        CY=Fore.CYAN; M=Fore.MAGENTA; W=Fore.WHITE
        BD=Style.BRIGHT; RS=Style.RESET_ALL
except ImportError:
    class C:
        R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
        CY="\033[96m"; M="\033[95m"; W="\033[97m"
        BD="\033[1m"; RS="\033[0m"

# ──────────────────────────────────────────────────────────────────────────────
#  Androguard (optional)
# ──────────────────────────────────────────────────────────────────────────────
_ANDROGUARD = False
_ag_apk     = None
for _mod in ("androguard.core.bytecodes.apk",):
    try:
        import importlib
        _m = importlib.import_module(_mod)
        _ag_apk = _m
        _ANDROGUARD = True
        break
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
#  Global config  (all overridable via env-vars or CLI flags)
# ──────────────────────────────────────────────────────────────────────────────
APKTOOL_JAR = os.environ.get("APKTOOL_JAR",  "apktool.jar")
KEYSTORE    = os.environ.get("KEYSTORE",     "unguard_debug.keystore")
KEY_ALIAS   = os.environ.get("KEY_ALIAS",    "unguard")
KEY_PASS    = os.environ.get("KEY_PASS",     "unguard")
ZIPALIGN    = os.environ.get("ZIPALIGN",     "zipalign")
APKSIGNER   = os.environ.get("APKSIGNER",    "apksigner")
BUNDLETOOL  = os.environ.get("BUNDLETOOL",   "bundletool.jar")
TOOL_NAME    = "UnGuard"
TOOL_VERSION = "1.0.0"
MAX_WORKERS  = int(os.environ.get("MAX_WORKERS", str(min(os.cpu_count() or 4, 8))))

# ──────────────────────────────────────────────────────────────────────────────
#  Thread-safe logger
# ──────────────────────────────────────────────────────────────────────────────
_PLOCK = threading.Lock()

# ──────────────────────────────────────────────────────────────────────────────
#  Progress bar  (thread-safe, works alongside log())
# ──────────────────────────────────────────────────────────────────────────────
class Progress:
    """ASCII progress bar that overwrites the same terminal line.
    Call done() to clear it and optionally print a final ok message.
    """
    BAR_W = 38

    def __init__(self, label: str, total: int):
        self.label   = label
        self.total   = max(total, 1)
        self.current = 0
        self._draw(0)

    def update(self, n: int):
        self.current = n
        self._draw(n)

    def inc(self):
        self.update(self.current + 1)

    def done(self, msg: str = ""):
        with _PLOCK:
            sys.stdout.write("\r" + " " * 82 + "\r")
            sys.stdout.flush()
        if msg:
            log("ok", msg)

    def _draw(self, n: int):
        pct    = min(n / self.total, 1.0)
        filled = int(self.BAR_W * pct)
        bar    = C.G + "█" * filled + C.CY + "░" * (self.BAR_W - filled) + C.RS
        ts     = time.strftime("%H:%M:%S")
        line   = (f"\r{C.CY}{ts}{C.RS} {C.CY}[~]{C.RS} "
                  f"{self.label}  [{bar}] "
                  f"{C.BD}{n}/{self.total}{C.RS} ({pct:.0%})")
        with _PLOCK:
            sys.stdout.write(line)
            sys.stdout.flush()

# ──────────────────────────────────────────────────────────────────────────────
#  Logger  (uniform format: HH:MM:SS [icon] message, no stray blank lines)
# ──────────────────────────────────────────────────────────────────────────────
_ICONS = {
    "info":   lambda: f"{C.CY}[*]{C.RS}",
    "ok":     lambda: f"{C.G}[+]{C.RS}",
    "warn":   lambda: f"{C.Y}[!]{C.RS}",
    "err":    lambda: f"{C.R}[x]{C.RS}",
    "patch":  lambda: f"{C.M}[P]{C.RS}",
    "detect": lambda: f"{C.B}[D]{C.RS}",
    "deob":   lambda: f"{C.Y}[O]{C.RS}",
    "var":    lambda: f"{C.BD}{C.G}[V]{C.RS}",
    "step":   lambda: f"{C.CY}[>]{C.RS}",
}

def log(lvl: str, msg: str, indent: int = 0):
    ts  = time.strftime("%H:%M:%S")
    pad = "  " * indent
    with _PLOCK:
        if lvl == "head":
            bar = f"{C.BD}{C.CY}{'─' * 60}{C.RS}"
            lbl = f"{C.BD}{C.CY}  {msg}{C.RS}"
            print(f"\n{bar}\n{lbl}\n{bar}")
        else:
            pfx = _ICONS.get(lvl, lambda: "[?]")()
            print(f"{C.CY}{ts}{C.RS} {pad}{pfx} {msg}")

def banner():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"""{C.BD}{C.CY}
  +============================================================+
  |  UnGuard v1.0.0  Android APK Patcher                      |
  |  --patch iap,integrity,ads,storageIO,serverIO,all         |
  |  Unity  Unreal  Flutter  Native   Multi-threaded          |
  |  DexGuard  Arxan  DashO  Custom obfuscation               |
  +============================================================+{C.RS}
  {C.CY}Started : {ts}   Workers : {MAX_WORKERS}{C.RS}
""")

# ──────────────────────────────────────────────────────────────────────────────
#  Patch category system
#
#  Each category is a string key.  The user picks one or more via --patch.
#  "all" expands to every category.
# ──────────────────────────────────────────────────────────────────────────────
PATCH_CATEGORIES = {
    "iap":       "IAP (Google Play / Amazon / Huawei / premium gates)",
    "integrity": "Integrity (Play Integrity / SafetyNet / LVL / signatures)",
    "ads":       "Ads (AdMob / Facebook / Unity / AppLovin / IronSource / …)",
    "storageIO": "Storage I/O (SQLite / Room / SharedPreferences flags)",
    "serverIO":  "Server I/O (JSON status / Retrofit / OkHttp response codes)",
}
ALL_PATCHES = frozenset(PATCH_CATEGORIES.keys())

# Case-insensitive lookup table: lowercase → canonical key
_PATCH_ALIASES = {k.lower(): k for k in PATCH_CATEGORIES}
# Common shorthand aliases
_PATCH_ALIASES.update({
    "storage": "storageIO", "storageio": "storageIO",
    "server":  "serverIO",  "serverio":  "serverIO",
    "server_io": "serverIO","storage_io": "storageIO",
    "network": "serverIO",
})

def parse_patches(raw: str) -> frozenset:
    """
    Parse the --patch argument.  Accepts:
      • comma-separated   : iap,integrity,ads
      • pipe-separated    : iap|integrity
      • mixed             : iap,ads|storageIO
      • 'all'             : every category
    Case-insensitive.  Returns frozenset of canonical patch keys.
    """
    tokens = re.split(r"[,|\s]+", raw.strip())
    result = set()
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if tok.lower() == "all":
            return ALL_PATCHES
        canonical = _PATCH_ALIASES.get(tok.lower())
        if canonical is None:
            raise ValueError(
                f"Unknown patch category '{tok}'. "
                f"Valid: {', '.join(sorted(PATCH_CATEGORIES))}, all  "
                f"(also: storage, server as shorthands)"
            )
        result.add(canonical)
    return frozenset(result)

def patches_to_slug(patches: frozenset) -> str:
    """Build a filename-safe slug from the chosen patch set."""
    if patches == ALL_PATCHES:
        return "all"
    return "_".join(sorted(patches))

def patches_to_label(patches: frozenset) -> str:
    """Build a human-readable label from the chosen patch set."""
    if patches == ALL_PATCHES:
        return "All patches (IAP + Integrity + Ads + Storage + Server)"
    return " + ".join(PATCH_CATEGORIES[p] for p in sorted(patches))

# ──────────────────────────────────────────────────────────────────────────────
#  Shared smali file cache
#  All engines (obf detection, patch detection, patching) share one load.
# ──────────────────────────────────────────────────────────────────────────────
class SmaliCache:
    """
    Loads every *.smali file once with sequential I/O (fastest on Android flash).
    Exposes the content dict so other engines avoid re-reading.
    """
    def __init__(self, base: str):
        self.base  = Path(base)
        self._data: dict[str, str] = {}   # rel_path → content
        self._loaded = False

    def load(self, show_progress: bool = True):
        if self._loaded:
            return
        t0 = time.time()
        # Enumerate first
        all_files = []
        for root, _, files in os.walk(str(self.base)):
            for fname in files:
                if fname.endswith(".smali"):
                    all_files.append(os.path.join(root, fname))
        total = len(all_files)
        pb = Progress("Loading smali", total) if show_progress and total > 50 else None
        for i, full in enumerate(all_files):
            rel = os.path.relpath(full, str(self.base))
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    self._data[rel] = fh.read()
            except Exception:
                self._data[rel] = ""
            if pb and (i % 100 == 0 or i == total - 1):
                pb.update(i + 1)
        if pb:
            pb.done(f"Loaded {total} smali files in {time.time()-t0:.1f}s")
        else:
            log("ok", f"Loaded {total} smali files in {time.time()-t0:.1f}s")
        self._loaded = True

    def invalidate(self):
        """Call after writing modified smali back to disk."""
        self._data.clear()
        self._loaded = False

    def items(self):
        return self._data.items()

    def all_rels(self) -> list[str]:
        return list(self._data.keys())

    def get(self, rel: str) -> str:
        return self._data.get(rel, "")

# ──────────────────────────────────────────────────────────────────────────────
#  Parallel pattern scanner (uses cache)
# ──────────────────────────────────────────────────────────────────────────────
class SmaliScanner:
    def __init__(self, cache: SmaliCache, workers: int = MAX_WORKERS):
        self.cache   = cache
        self.workers = workers

    def scan(self, patterns: list[tuple[str,str]],
             label: str = "Scanning") -> dict[str, set[str]]:
        """Returns {tag: set(rel_path)}. Shows progress bar."""
        compiled = [(re.compile(p, re.IGNORECASE), t) for p, t in patterns]
        bucket   = defaultdict(set)
        lock     = threading.Lock()
        items    = list(self.cache.items())
        total    = len(items)
        done_n   = [0]
        pb       = Progress(label, total) if total > 50 else None

        def _work(item):
            rel, text = item
            if not text:
                return []
            return [(t, rel) for pat, t in compiled if pat.search(text)]

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for hits in ex.map(_work, items):
                for t, rel in hits:
                    with lock:
                        bucket[t].add(rel)
                done_n[0] += 1
                if pb and (done_n[0] % 100 == 0 or done_n[0] == total):
                    pb.update(done_n[0])

        if pb:
            pb.done()
        return dict(bucket)

# ──────────────────────────────────────────────────────────────────────────────
#  Smali patching helpers
# ──────────────────────────────────────────────────────────────────────────────

def _method_end(lines: list[str], start: int) -> int | None:
    """Return index of '.end method' line, or None."""
    for j in range(start + 1, len(lines)):
        if lines[j].strip().startswith(".end method"):
            return j
    return None

def _extract_registers_line(lines: list[str], start: int, end: int) -> str | None:
    """
    Return the first '.locals N' or '.registers N' line inside a method,
    or None if not found.
    """
    for j in range(start + 1, end):
        s = lines[j].strip()
        if s.startswith(".locals ") or s.startswith(".registers "):
            return lines[j]
    return None

def _max_reg_index(lines: list[str], start: int, end: int) -> int:
    """
    Scan a method body for the highest vN register used.
    Returns the count needed for .locals.
    """
    highest = -1
    for j in range(start + 1, end):
        for m in re.finditer(r"\bv(\d+)\b", lines[j]):
            highest = max(highest, int(m.group(1)))
    return highest + 1  # locals count

def _safe_replace_body(lines: list[str], start: int, end: int,
                       new_body: list[str], locals_n: int) -> list[str]:
    """
    Replace the body of a smali method (between .method and .end method)
    with new_body, always inserting a valid .locals directive first.
    Preserves all lines before start and all lines after end (inclusive).
    """
    locals_line = f"    .locals {locals_n}\n"
    # lines[:start+1]  = everything up to and including .method declaration
    # [locals_line]    = mandatory .locals N directive
    # new_body         = replacement instructions
    # [lines[end]]     = .end method line
    # lines[end+1:]    = everything after this method (MUST NOT be dropped)
    return lines[:start+1] + [locals_line] + new_body + [lines[end]] + lines[end+1:]

# ──────────────────────────────────────────────────────────────────────────────
#  Patch Engine – IAP / Integrity / Storage / Server
# ──────────────────────────────────────────────────────────────────────────────
class PatchEngine:

    # ── Detection pattern banks ───────────────────────────────────────────────
    IAP_PATTERNS = [
        (r"Lcom/android/billingclient/api/BillingClient;",             "gplay"),
        (r"Lcom/android/billingclient/api/PurchasesUpdatedListener;",  "gplay"),
        (r"Lcom/android/billingclient/api/ProductDetails;",            "gplay"),
        (r"Lcom/android/billingclient/api/BillingFlowParams;",         "gplay"),
        (r"Lcom/android/billingclient/api/ConsumeParams;",             "gplay"),
        (r"Lcom/android/billingclient/api/Purchase;",                  "gplay"),
        (r"->launchBillingFlow",                                       "gplay"),
        (r"->queryProductDetailsAsync",                                "gplay"),
        (r"->acknowledgePurchase",                                     "gplay"),
        (r"->consumeAsync",                                            "gplay"),
        (r"Lcom/amazon/device/iap/PurchasingService;",                 "amazon"),
        (r"Lcom/amazon/device/iap/model/Receipt;",                     "amazon"),
        (r"Lcom/huawei/hms/iap/IapClient;",                           "huawei"),
        (r"Lcom/huawei/hms/iap/entity/InAppPurchaseData;",            "huawei"),
        (r"purchase|billing|ProductDetails|SKU_DETAILS",              "generic"),
        (r"isPremium|isSubscribed|hasPurchased|isPurchased",          "generic"),
        (r"PURCHASE_STATE_PURCHASED|purchaseState",                   "generic"),
    ]
    INTEGRITY_PATTERNS = [
        (r"Lcom/google/android/play/core/integrity/IntegrityManager;",           "play_int"),
        (r"Lcom/google/android/play/core/integrity/IntegrityTokenResponse;",     "play_int"),
        (r"->requestIntegrityToken",                                              "play_int"),
        (r"Lcom/google/android/play/core/integrity/StandardIntegrityManager;",   "play_int"),
        (r"Lcom/google/android/gms/safetynet/SafetyNet;",                        "safetynet"),
        (r"->attest\(",                                                           "safetynet"),
        (r"Lcom/android/vending/licensing/LicenseChecker;",                      "lvl"),
        (r"Lcom/android/vending/licensing/LicenseValidator;",                    "lvl"),
        (r"->getPackageManager",                                                  "sig"),
        (r"->getPackageInfo",                                                     "sig"),
        (r"->signatures",                                                         "sig"),
        (r"->getInstallerPackageName",                                            "sig"),
        (r"isDatabaseIntegrityOk",                                               "dbint"),
        (r"WEBVIEW_MEDIA_INTEGRITY",                                             "wvint"),
        (r"checkValidity|verifyPurchase|validateReceipt|checkAppIntegrity",      "custom"),
    ]
    STORAGE_PATTERNS = [
        (r"Landroid/database/sqlite/SQLiteDatabase;->rawQuery\(",                 "sqlite"),
        (r"Landroid/database/sqlite/SQLiteDatabase;->query\(",                    "sqlite"),
        (r"Landroid/database/Cursor;->getInt\(",                                  "cursor"),
        (r"Landroid/database/Cursor;->getString\(",                               "cursor"),
        (r"Landroidx/room/RoomDatabase;",                                         "room"),
        (r"Landroid/content/SharedPreferences;->getInt\(",                        "sprefs"),
        (r"Landroid/content/SharedPreferences;->getBoolean\(",                    "sprefs"),
        (r"isPremium|isUnlocked|premium_user|subscription_active|has_purchased",  "flag"),
    ]
    SERVER_PATTERNS = [
        (r"Lorg/json/JSONObject;->(?:getInt|optInt)\(",                           "json"),
        (r"Lorg/json/JSONObject;->(?:getBoolean|optBoolean)\(",                  "json"),
        (r"Lorg/json/JSONObject;->(?:getString|optString)\(",                    "json"),
        (r"Lretrofit2/Response;->(?:code|isSuccessful)\(",                       "retrofit"),
        (r"Lokhttp3/Response;->(?:code|isSuccessful)\(",                         "okhttp"),
        (r"purchaseState|statusCode|status_code|result_code|"
         r"resultCode|errorCode|error_code|responseCode",                         "status"),
        (r'"status"|"code"|"result"|"success"|"active"|"subscribed"',            "json_key"),
        (r"Ljava/net/HttpURLConnection;->getResponseCode\(",                      "urlconn"),
    ]

    # ── Ads SDK detection patterns ─────────────────────────────────────────────
    ADS_PATTERNS = [
        # Google AdMob / Google Ads
        (r"Lcom/google/android/gms/ads/",                                  "admob"),
        (r"Lcom/google/ads/",                                              "admob"),
        (r"->loadAd\(",                                                    "admob"),
        (r"->loadInterstitial\(",                                          "admob"),
        # Facebook Audience Network
        (r"Lcom/facebook/ads/",                                            "fb_ads"),
        (r"Lcom/facebook/audience_network/",                               "fb_ads"),
        # Unity Ads
        (r"Lcom/unity3d/ads/",                                             "unity_ads"),
        (r"Lcom/unity3d/services/ads/",                                    "unity_ads"),
        # AppLovin MAX
        (r"Lcom/applovin/",                                                "applovin"),
        (r"Lcom/adjust/sdk/",                                              "applovin"),
        # IronSource
        (r"Lcom/ironsource/",                                              "ironsource"),
        (r"Lcom/supersonicads/",                                           "ironsource"),
        # MoPub / Twitter Ads
        (r"Lcom/mopub/",                                                   "mopub"),
        # Vungle
        (r"Lcom/vungle/",                                                  "vungle"),
        (r"Lcom/vungle/warren/",                                           "vungle"),
        # InMobi
        (r"Lcom/inmobi/",                                                  "inmobi"),
        # Chartboost
        (r"Lcom/chartboost/",                                              "chartboost"),
        # Tapjoy
        (r"Lcom/tapjoy/",                                                  "tapjoy"),
        # Pangle / TikTok
        (r"Lcom/bytedance/sdk/openadsdk/",                                 "pangle"),
        (r"Lcom/ss/android/ugc/aweme/",                                    "pangle"),
        # Ogury
        (r"Lco/ogury/",                                                    "ogury"),
        # Digital Turbine / Fyber
        (r"Lcom/fyber/",                                                   "fyber"),
        (r"Lcom/digitalturbine/",                                          "fyber"),
        # Snap Audience Network
        (r"Lcom/snap/",                                                    "snap_ads"),
        # Liftoff / Vungle
        (r"Lcom/liftoff/",                                                 "liftoff"),
        # Generic ad patterns
        (r"AdView|AdRequest|AdListener|AdLoader|AdUnit",                   "generic_ad"),
        (r"->showAd\(|->showInterstitial\(|->showRewarded\(",           "generic_ad"),
        (r"->loadBannerAd\(|->loadRewardedAd\(|->loadNativeAd\(",      "generic_ad"),
    ]

    # ── Ads method-name regexes ────────────────────────────────────────────────
    # load* methods → return-void (stop ads fetching network)
    _ADS_LOAD_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:loadAd|loadInterstitial|loadInterstitialAd|loadBannerAd|"
        r"loadRewardedAd|loadRewardedInterstitialAd|loadNativeAd|"
        r"loadNativeExpressAd|loadAppOpenAd|loadOfferWall|loadVideo|"
        r"fetchAd|fetchInterstitial|fetchBanner|requestAd|requestBanner|"
        r"preloadAd|preloadInterstitial|cacheInterstitial|cacheVideo|"
        r"prepareAd|prepareInterstitial|initAd|initBanner|initInterstitial)\("
    )
    # show* methods → return-void (block ad display)
    _ADS_SHOW_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:showAd|showInterstitial|showInterstitialAd|showRewarded|"
        r"showRewardedAd|showRewardedInterstitialAd|showAppOpenAd|"
        r"showVideo|showOfferWall|show|displayAd|displayInterstitial|"
        r"presentAd|presentInterstitial|playVideo|playAd)\("
    )
    # isLoaded / isReady → return false (so app won't attempt show)
    _ADS_READY_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:isAdLoaded|isLoaded|isReady|isInterstitialReady|isVideoReady|"
        r"isRewardedVideoReady|isOfferWallReady|isBannerLoaded|"
        r"isInitialized|isAdAvailable|hasAd|isAdReady)\(\)Z"
    )

    # Method-name regexes (applied to the .method declaration line)
    _PURCHASE_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final|synchronized)\s+)*"
        r"(?:purchase|buy|startPurchase|initPurchase|doPurchase|"
        r"launchPurchase|beginPurchase|onPurchase|processPurchase|"
        r"handlePurchase|completePurchase|triggerPurchase|makePurchase|"
        r"requestPurchase|launchBillingFlow|buyProduct|orderProduct)\("
    )
    _BOOL_GATE_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:isPremium|isUnlocked|isPurchased|isSubscribed|hasPurchased|"
        r"checkPremium|isLicensed|isActivated|isProUser|isProVersion|"
        r"isFullVersion|isBought|hasFullAccess|isPaid|isVip|isVIP|"
        r"isPro|isActive|isMember|hasSubscription|isEntitled)\(\)Z"
    )
    _INTEGRITY_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:requestIntegrityToken|attest|checkLicense|verifySignature|"
        r"checkSignature|checkAppIntegrity|onIntegrityToken|validateIntegrity|"
        r"onFailure|verifyInstall|validateToken|verifyDevice|"
        r"handleIntegrityResult|processIntegrityToken)\("
    )

    def __init__(self, base: str, cache: SmaliCache, workers: int = MAX_WORKERS):
        self.base    = base
        self.cache   = cache
        self.scanner = SmaliScanner(cache, workers)
        self.workers = workers
        self._iap: set[str] = set()
        self._int: set[str] = set()
        self._sto: set[str] = set()
        self._srv: set[str] = set()
        self._ads: set[str] = set()

    # ── Detection ─────────────────────────────────────────────────────────────
    def find_all(self):
        log("head", "Detection Phase")
        t0 = time.time()
        all_pats = (self.IAP_PATTERNS + self.INTEGRITY_PATTERNS
                    + self.STORAGE_PATTERNS + self.SERVER_PATTERNS
                    + self.ADS_PATTERNS)
        res = self.scanner.scan(all_pats, label="API pattern scan")

        iap_t = {t for _, t in self.IAP_PATTERNS}
        int_t = {t for _, t in self.INTEGRITY_PATTERNS}
        sto_t = {t for _, t in self.STORAGE_PATTERNS}
        srv_t = {t for _, t in self.SERVER_PATTERNS}
        ads_t = {t for _, t in self.ADS_PATTERNS}

        for tag, files in res.items():
            for f in files:
                if tag in iap_t: self._iap.add(f)
                if tag in int_t: self._int.add(f)
                if tag in sto_t: self._sto.add(f)
                if tag in srv_t: self._srv.add(f)
                if tag in ads_t: self._ads.add(f)

        log("ok", f"IAP files       : {C.BD}{len(self._iap)}{C.RS}")
        log("ok", f"Integrity files : {C.BD}{len(self._int)}{C.RS}")
        log("ok", f"Ads files       : {C.BD}{len(self._ads)}{C.RS}")
        log("ok", f"Storage files   : {C.BD}{len(self._sto)}{C.RS}")
        log("ok", f"Server-reply    : {C.BD}{len(self._srv)}{C.RS}")
        log("ok", f"Scan time       : {time.time()-t0:.1f}s")

    # ── IAP patching ──────────────────────────────────────────────────────────
    def patch_iap(self) -> int:
        if not self._iap:
            log("warn", "No IAP files – skip."); return 0
        log("info", f"Patching IAP ({len(self._iap)} files)…")
        total = sum(self._patch_iap_file(f) for f in self._iap)
        log("ok",  f"IAP: {C.G}{total}{C.RS} patches applied.")
        return total

    def _patch_iap_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        patched = 0
        i = 0
        while i < len(lines):
            stripped = lines[i].rstrip()

            # ── Purchase method: replace body with fake success ───────────────
            if self._PURCHASE_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                cb  = self._find_callback(lines, i, end)
                nb  = self._iap_success_body(cb)
                # Need v0 + v1 for StringBuilder chain = 2 locals
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1)
                patched += 1
                log("patch", f"IAP purchase  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)   # skip past inserted block
                continue

            # ── Boolean gate: isPremium() → return true ───────────────────────
            if self._BOOL_GATE_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                nb  = ["    const/4 v0, 0x1\n", "    return v0\n"]
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1)
                patched += 1
                log("patch", f"IAP bool gate  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)
                continue

            # ── BillingResponseCode → 0 (OK) inline ──────────────────────────
            if ("BillingResult;->getResponseCode()I" in stripped
                    and "invoke-virtual" in stripped):
                # next non-blank line should be move-result
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines):
                    m = re.match(r"([ \t]+)(move-result)\s+([vp]\d+)", lines[j])
                    if m:
                        reg = m.group(3)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x0  # UNGUARD: BillingResponseCode=OK\n")
                        patched += 1
                        i = j + 2; continue

            i += 1

        if patched:
            open(path, "w", encoding="utf-8").writelines(lines)
        return patched

    @staticmethod
    def _iap_success_body(cb) -> list[str]:
        """
        Build minimal valid smali that delivers a fake purchase JSON string
        to the success callback (if found) then returns void.
        Uses only v0 → .locals 1 is sufficient.
        """
        json_str = '{"productId":"bypass","purchaseToken":"unguard","purchaseState":1}'
        body = [f'    const-string v0, "{json_str}"\n']
        if cb:
            body.append(f"    invoke-static {{v0}}, {cb[0]}->{cb[1]}(Ljava/lang/String;)V\n")
        body.append("    return-void\n")
        return body

    @staticmethod
    def _find_callback(lines, start, end):
        for k in range(start, end):
            m = re.search(
                r"invoke-static \{[^}]*\}, (L[^;]+;)->([^(]+)\(Ljava/lang/String;\)V",
                lines[k])
            if m: return m.group(1), m.group(2)
        return None

    # ── Integrity patching ────────────────────────────────────────────────────
    def patch_integrity(self) -> int:
        if not self._int:
            log("warn", "No integrity files – skip."); return 0
        log("info", f"Patching integrity ({len(self._int)} files)…")
        total = sum(self._patch_integrity_file(f) for f in self._int)
        log("ok",  f"Integrity: {C.G}{total}{C.RS} patches applied.")
        return total

    def _patch_integrity_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        patched = 0
        i = 0
        while i < len(lines):
            stripped = lines[i].rstrip()
            if self._INTEGRITY_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                # Determine return type from method descriptor
                ret_m = re.search(r"\)([ZVI]|L[^;]+;)$", stripped)
                rt    = ret_m.group(1) if ret_m else "V"
                if rt == "Z":
                    nb = ["    const/4 v0, 0x1\n", "    return v0\n"]
                    loc = 1
                elif rt == "V":
                    nb  = ["    return-void\n"]
                    loc = 0
                else:
                    nb  = ["    const/4 v0, 0x0\n", "    return-object v0\n"]
                    loc = 1
                lines = _safe_replace_body(lines, i, end, nb, loc)
                patched += 1
                log("patch", f"Integrity  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)
                continue

            # Nop signature checks inline
            if "->signatures" in stripped or "->getInstallerPackageName" in stripped:
                lines[i] = f"    # UNGUARD-NOP: {stripped.strip()}\n"
                patched  += 1

            i += 1

        if patched:
            open(path, "w", encoding="utf-8").writelines(lines)
        return patched

    # ── Storage patching ──────────────────────────────────────────────────────
    def patch_storage(self) -> int:
        if not self._sto:
            log("warn", "No storage files – skip."); return 0
        log("info", f"Patching storage ({len(self._sto)} files)…")
        total = sum(self._patch_storage_file(f) for f in self._sto)
        log("ok",  f"Storage: {C.G}{total}{C.RS} patches applied.")
        return total

    # Premium-flag keywords for SharedPreferences/Cursor key detection
    _PREM_KEYS = re.compile(
        r'const-string\s+[vp]\d+,\s*"(?:'
        r'premium|subscription|unlocked|purchaseState|status|'
        r'activated|active|pro|licensed|bought|is_premium|is_active|'
        r'has_purchased|subscription_active|isPremium|isUnlocked|'
        r'is_subscribed|isSubscribed|isPaid|isVip|isMember|'
        r'entitle|feature_unlock|full_version)[^"]*"',
        re.IGNORECASE,
    )

    def _patch_storage_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        n_tot = 0
        i = 0
        while i < len(lines):
            s = lines[i].strip()

            # SharedPreferences.getBoolean → force true
            if ("SharedPreferences;->getBoolean" in s and "invoke-" in s):
                reg = self._next_move_result(lines, i)
                if reg:
                    j = self._next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/4 {reg}, 0x1  # UNGUARD: getBoolean=true\n")
                    n_tot += 1; i = j + 2; continue

            # SharedPreferences.getInt near a premium key → force 1
            if ("SharedPreferences;->getInt" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=6):
                    reg = self._next_move_result(lines, i)
                    if reg:
                        j = self._next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: getInt(prem)=1\n")
                        n_tot += 1; i = j + 2; continue

            # Cursor.getInt near a premium key → force 1
            if ("Cursor;->getInt(" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=8):
                    reg = self._next_move_result(lines, i)
                    if reg:
                        j = self._next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: cursor.getInt(prem)=1\n")
                        n_tot += 1; i = j + 2; continue

            # Room DAO premium/status query → force 1
            if ("Dao;->" in s and "invoke-interface" in s and
                    re.search(r"->(?:isPremium|isUnlocked|getStatus|getSubscription)\(\)", s)):
                reg = self._next_move_result(lines, i)
                if reg:
                    j = self._next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/4 {reg}, 0x1  # UNGUARD: Room DAO prem=1\n")
                    n_tot += 1; i = j + 2; continue

            i += 1

        if n_tot:
            open(path, "w", encoding="utf-8").writelines(lines)
            log("patch", f"Storage  {rel}  ({n_tot}x)", indent=1)
        return n_tot

    def _near_prem_key(self, lines, idx, lookback=6) -> bool:
        """Check fixed window first, then entire enclosing method body."""
        start = max(0, idx - lookback)
        if self._PREM_KEYS.search("".join(lines[start:idx+1])): return True
        # Fallback: scan whole method
        ms = idx
        while ms > 0 and not lines[ms].strip().startswith('.method'): ms -= 1
        me = idx + 1
        while me < len(lines) and not lines[me].strip().startswith('.end method'): me += 1
        return bool(self._PREM_KEYS.search("".join(lines[ms:me+1])))

    @staticmethod
    def _next_move_result_idx(lines: list[str], from_idx: int) -> int | None:
        """Return the line index of the next move-result after from_idx."""
        for j in range(from_idx + 1, min(from_idx + 5, len(lines))):
            s = lines[j].strip()
            if re.match(r"move-result(?:-object|-wide)?\s+[vp]\d+", s):
                return j
        return None

    @staticmethod
    def _next_move_result(lines: list[str], from_idx: int) -> str | None:
        """Return register name (e.g. 'v0') of the next move-result."""
        for j in range(from_idx + 1, min(from_idx + 5, len(lines))):
            m = re.match(r"[ \t]*move-result(?:-object|-wide)?\s+([vp]\d+)", lines[j])
            if m: return m.group(1)
        return None

    # ── Server-reply patching ─────────────────────────────────────────────────
    def patch_server_replies(self) -> int:
        if not self._srv:
            log("warn", "No server-reply files – skip."); return 0
        log("info", f"Patching server replies ({len(self._srv)} files)…")
        total = sum(self._patch_server_file(f) for f in self._srv)
        log("ok",  f"Server-reply: {C.G}{total}{C.RS} patches applied.")
        return total

    _STATUS_KEYS = re.compile(
        r'const-string\s+[vp]\d+,\s*"(?:'
        r'status|code|result|purchaseState|errorCode|statusCode|'
        r'result_code|error_code|purchase_state|responseCode|'
        r'success|active|premium|subscribed|valid|verified|'
        r'enabled|isActive|isPremium|is_premium|is_active|'
        r'purchase_status|order_status|payment_status|'
        r'license_status|subscription_status)[^"]*"',
        re.IGNORECASE,
    )

    def _patch_server_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        n_tot = 0
        i = 0
        while i < len(lines):
            s = lines[i].strip()

            # JSONObject.getInt/optInt near status key → force 1
            if ("JSONObject;->getInt(" in s or "JSONObject;->optInt(" in s):
                if self._near_status_key(lines, i, lookback=5):
                    reg = self._next_move_result(lines, i)
                    if reg:
                        j = self._next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSON int=1\n")
                        n_tot += 1; i = j + 2; continue

            # JSONObject.getBoolean/optBoolean near status/success key → force true
            if ("JSONObject;->getBoolean(" in s or "JSONObject;->optBoolean(" in s):
                if self._near_status_key(lines, i, lookback=5):
                    reg = self._next_move_result(lines, i)
                    if reg:
                        j = self._next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSON bool=true\n")
                        n_tot += 1; i = j + 2; continue

            # Retrofit2 / OkHttp .code() → 200
            if (("retrofit2/Response;->code()" in s or
                 "okhttp3/Response;->code()" in s) and "invoke-virtual" in s):
                reg = self._next_move_result(lines, i)
                if reg:
                    j = self._next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    n_tot += 1; i = j + 2; continue

            # Retrofit2 / OkHttp .isSuccessful() → true
            if (("retrofit2/Response;->isSuccessful()" in s or
                 "okhttp3/Response;->isSuccessful()" in s) and "invoke-virtual" in s):
                reg = self._next_move_result(lines, i)
                if reg:
                    j = self._next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/4 {reg}, 0x1  # UNGUARD: isSuccessful=true\n")
                    n_tot += 1; i = j + 2; continue

            # HttpURLConnection.getResponseCode() → 200
            if ("HttpURLConnection;->getResponseCode()" in s and "invoke-virtual" in s):
                reg = self._next_move_result(lines, i)
                if reg:
                    j = self._next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    n_tot += 1; i = j + 2; continue

            # JSONArray.length() near status context → force 1 (non-empty)
            if ("JSONArray;->length()" in s and "invoke-virtual" in s):
                if self._near_status_key(lines, i, lookback=8):
                    reg = self._next_move_result(lines, i)
                    if reg:
                        j = self._next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSONArray.length=1\n")
                        n_tot += 1; i = j + 2; continue

            i += 1

        if n_tot:
            open(path, "w", encoding="utf-8").writelines(lines)
            log("patch", f"Server  {rel}  ({n_tot}x)", indent=1)
        return n_tot

    def _near_status_key(self, lines, idx, lookback=5) -> bool:
        """Check fixed window first, then entire enclosing method body."""
        start = max(0, idx - lookback)
        if self._STATUS_KEYS.search("".join(lines[start:idx+1])): return True
        # Fallback: scan whole method
        ms = idx
        while ms > 0 and not lines[ms].strip().startswith('.method'): ms -= 1
        me = idx + 1
        while me < len(lines) and not lines[me].strip().startswith('.end method'): me += 1
        return bool(self._STATUS_KEYS.search("".join(lines[ms:me+1])))

    # ── Ads patching ──────────────────────────────────────────────────────────
    def patch_ads(self) -> int:
        """
        Bypass in-app advertisements by patching ad SDK calls in smali.

        Strategy:
          1. load* methods → replace body with return-void
             (stops the SDK from fetching ads from the network)
          2. show* methods → replace body with return-void
             (stops ads from being displayed)
          3. isLoaded / isReady → replace body with return false
             (prevents the app crashing when it checks before showing)
          4. Inline ad load/show invoke calls → nop'd with a comment
             (catches direct SDK invocations that aren't wrapped in methods)
        """
        if not self._ads:
            log("warn", "No ad SDK files – skip."); return 0
        log("info", f"Patching ads ({len(self._ads)} files)…")
        total = sum(self._patch_ads_file(f) for f in self._ads)
        log("ok",  f"Ads: {C.G}{total}{C.RS} patches applied.")
        return total

    def _patch_ads_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        patched = 0
        i = 0
        while i < len(lines):
            stripped = lines[i].rstrip()

            # ── load* method: stop ad fetching ───────────────────────────────
            if self._ADS_LOAD_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                nb  = ["    return-void\n"]
                lines = _safe_replace_body(lines, i, end, nb, locals_n=0)
                patched += 1
                log("patch", f"Ads load nop  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb); continue

            # ── show* method: suppress ad display ─────────────────────────────
            if self._ADS_SHOW_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                nb  = ["    return-void\n"]
                lines = _safe_replace_body(lines, i, end, nb, locals_n=0)
                patched += 1
                log("patch", f"Ads show nop  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb); continue

            # ── isLoaded / isReady: return false so app won't crash ───────────
            if self._ADS_READY_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                nb  = ["    const/4 v0, 0x0\n", "    return v0\n"]
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1)
                patched += 1
                log("patch", f"Ads isReady→false  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb); continue

            # ── Inline nop: direct SDK load/show invoke calls ─────────────────
            s = stripped
            # Ad load invocations
            _AD_LOAD_INVOKE = (
                "->loadAd(", "->loadInterstitial(", "->loadBannerAd(",
                "->loadRewardedAd(", "->loadNativeAd(", "->loadAppOpenAd(",
                "->fetchAd(", "->preloadAd(", "->cacheInterstitial(",
                "->loadOffer(", "->loadRewardedInterstitialAd(",
            )
            _AD_SHOW_INVOKE = (
                "->showAd(", "->showInterstitial(", "->showRewarded(",
                "->showRewardedAd(", "->showVideo(", "->showOfferWall(",
                "->presentAd(", "->displayAd(", "->playVideo(",
                "->showAppOpenAd(", "->showRewardedInterstitialAd(",
            )
            if (any(sig in s for sig in _AD_LOAD_INVOKE) and
                    ("invoke-" in s or "invoke-virtual" in s or "invoke-interface" in s)):
                lines[i] = f"    # UNGUARD-ADS: load nop'd: {stripped.strip()}\n"
                # Also nop the move-result-object on the next non-empty line if any
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines) and re.match(r"[ \t]+move-result(?:-object|-wide)?\s", lines[j]):
                    lines[j] = "    # UNGUARD-ADS: move-result nop'd\n"
                    patched += 1
                patched += 1
                i += 1; continue

            if (any(sig in s for sig in _AD_SHOW_INVOKE) and
                    "invoke-" in s):
                lines[i] = f"    # UNGUARD-ADS: show nop'd: {stripped.strip()}\n"
                patched += 1
                i += 1; continue

            i += 1

        if patched:
            open(path, "w", encoding="utf-8").writelines(lines)
        return patched

# ──────────────────────────────────────────────────────────────────────────────
#  Custom Obfuscation Engine (uses shared cache)
# ──────────────────────────────────────────────────────────────────────────────
class CustomObfuscationEngine:
    """
    Detects and deobfuscates custom obfuscation patterns.
    Uses the shared SmaliCache – no extra I/O.
    """
    _XOR_MARKERS  = frozenset(["xor-int","aget-byte","aput-byte",
                                "array-length","ushr-int/lit8","and-int/lit8"])
    _AES_RE       = re.compile(r'const-string\s+[vp]\d+,\s*"(?:AES|DES|Blowfish|RC4)[^"]*"', re.I)
    _NATIVE_RE    = re.compile(r"\.method\s+(?:\S+\s+)*native\s+\S+\([^)]*\)Ljava/lang/String;")
    _PACKER_RE    = re.compile(r"Ldalvik/system/(?:Dex|Path|InMemoryDex)ClassLoader;", re.I)
    _STR_ARR_RE   = re.compile(r"(?:[ \t]+const-string\s+[vp]\d+,\s*\"[^\"\n]{0,128}\"\n){5,}", re.M)
    _REFLECT_RE   = re.compile(r"Ljava/lang/reflect/Method;->invoke\("
                               r"|Ljava/lang/Class;->(?:getDeclared)?Method\(", re.I)
    _OPAQUE_RE    = re.compile(
        r"([ \t]+const(?:/4|/16)?\s+(?P<r>[vp]\d+),\s*(?P<v>0x0|0x1|0)\n)"
        r"([ \t]+if-(?P<op>eqz|nez|gtz|ltz|gez|lez)\s+(?P=r),\s*:(?P<lbl>\w+)\n)",
        re.M)
    _DEAD_GOTO_RE = re.compile(
        r"([ \t]+goto(?:/\d+)?\s+:(\w+)\n(?:[ \t]*:\w+\n)*"
        r"[ \t]+goto(?:/\d+)?\s+:\2\n)", re.M)
    _SB_CHAIN_RE  = re.compile(
        r"(?:[ \t]+const-string\s+[vp]\d+,\s*\"(?P<s>[^\"\n]{0,128})\"\n"
        r"[ \t]+invoke-virtual\s+\{[^}]+\},\s*Ljava/lang/StringBuilder;"
        r"->append\(Ljava/lang/String;\)Ljava/lang/StringBuilder;\n){3,}", re.M)

    WEIGHTS = {
        "xor":10, "aes":20, "native":25, "packer":30,
        "strarray":10, "sb_concat":5, "opaque":5, "reflect":5,
    }

    def __init__(self, cache: SmaliCache, workers: int = MAX_WORKERS):
        self.cache   = cache
        self.workers = workers
        self.report: dict[str, list[str]] = defaultdict(list)
        self.score   = 0

    def detect(self) -> dict:
        log("head", "Custom Obfuscation Detection")
        items = list(self.cache.items())
        lock  = threading.Lock()
        counts: dict[str, int] = defaultdict(int)

        def _scan(item):
            rel, text = item
            if not text: return {}
            hits: dict[str, int] = {}
            found: dict[str, bool] = {}

            # XOR stubs
            n = self._count_xor_stubs(text)
            if n: hits["xor"] = n; found["xor"] = True

            if self._AES_RE.search(text):      hits["aes"]      = 1; found["aes"]      = True
            if self._NATIVE_RE.search(text):   hits["native"]   = 1; found["native"]   = True
            if self._PACKER_RE.search(text):   hits["packer"]   = 1; found["packer"]   = True
            if self._STR_ARR_RE.search(text):  hits["strarray"] = 1; found["strarray"] = True

            sb = len(self._SB_CHAIN_RE.findall(text))
            if sb >= 2: hits["sb_concat"] = 1; found["sb_concat"] = True

            op = len(self._OPAQUE_RE.findall(text))
            if op >= 3: hits["opaque"] = op; found["opaque"] = True

            rf = len(self._REFLECT_RE.findall(text))
            if rf >= 2: hits["reflect"] = rf; found["reflect"] = True

            if found:
                with lock:
                    for k in found:
                        self.report[k].append(rel)
            return hits

        total  = len(items)
        done_n = [0]
        pb     = Progress("Obfuscation scan", total) if total > 50 else None
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for h in ex.map(_scan, items):
                for k, v in h.items():
                    counts[k] += v
                done_n[0] += 1
                if pb and (done_n[0] % 100 == 0 or done_n[0] == total):
                    pb.update(done_n[0])
        if pb:
            pb.done()

        for k, v in counts.items():
            if v > 0: self.score += self.WEIGHTS.get(k, 5)
        self.score = min(self.score, 100)

        if self.report:
            LABELS = {
                "xor":"XOR string encrypt","aes":"AES/cipher stubs",
                "native":"Native JNI decrypt","packer":"DexClassLoader packer",
                "strarray":"String-array table","sb_concat":"StringBuilder chain",
                "opaque":"Opaque predicates","reflect":"Reflection hiding",
            }
            for k, flist in self.report.items():
                log("detect", f"{C.BD}{LABELS.get(k,k).upper()}{C.RS}"
                    f"  ({len(flist)} file(s))", indent=1)
            log("warn", f"Custom obfuscation score: {C.BD}{self.score}/100{C.RS}")
        else:
            log("ok", "No custom obfuscation detected.")
        return dict(self.report)

    def deobfuscate(self) -> int:
        log("head", "Deobfuscation Phase")
        lock  = threading.Lock()
        total = 0

        def _deob(item) -> int:
            rel, orig = item
            if not orig: return 0
            text  = orig
            count = 0

            text, n = self._remove_opaques(text);   count += n
            text, n = self._collapse_dead_gotos(text); count += n
            text, n = self._annotate_sb_chains(text); count += n
            text, n = self._annotate_xor(text);      count += n
            text, n = self._annotate_aes(text);      count += n
            text, n = self._annotate_native(text);   count += n
            text, n = self._annotate_strarray(text); count += n

            if text != orig:
                path = self.cache.base / rel
                try:    path.write_text(text, encoding="utf-8")
                except: return 0
            return count

        items  = list(self.cache.items())
        count  = len(items)
        done_n = [0]
        pb     = Progress("Deobfuscating", count) if count > 50 else None
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for n in ex.map(_deob, items):
                total  += n
                done_n[0] += 1
                if pb and (done_n[0] % 100 == 0 or done_n[0] == count):
                    pb.update(done_n[0])
        if pb:
            pb.done(f"Deobfuscation complete: {total} transforms applied.")
        else:
            log("ok", f"Deobfuscation: {total} transforms applied.")
        return total

    # ── Detection helpers ─────────────────────────────────────────────────────
    def _count_xor_stubs(self, text: str) -> int:
        count = 0
        for m in re.finditer(
                r"\.method\b[^\n]*\)Ljava/lang/String;\n(.*?)\.end method",
                text, re.DOTALL):
            body = m.group(1)
            if sum(1 for mk in self._XOR_MARKERS if mk in body) >= 2:
                count += 1
        return count

    # ── Deobfuscation transforms ──────────────────────────────────────────────
    def _remove_opaques(self, text: str) -> tuple[str, int]:
        n = 0
        def _r(m):
            nonlocal n
            val = m.group("v"); op = m.group("op"); lbl = m.group("lbl")
            zero = val in ("0x0","0")
            TAKEN = {("eqz",True),("nez",False),("lez",True),("gez",True)}
            NEVER = {("eqz",False),("nez",True),("lez",False),("gez",False)}
            if (op, zero) in TAKEN:
                n += 1; return f"    # UNGUARD-DEOB: opaque→always-taken\n    goto :{lbl}\n"
            if (op, zero) in NEVER:
                n += 1; return f"    # UNGUARD-DEOB: opaque→never-taken\n"
            return m.group(0)
        return self._OPAQUE_RE.sub(_r, text), n

    def _collapse_dead_gotos(self, text: str) -> tuple[str, int]:
        t, n = self._DEAD_GOTO_RE.subn(
            lambda m: f"    # UNGUARD-DEOB: dead-goto collapsed\n    goto :{m.group(2)}\n", text)
        return t, n

    def _annotate_sb_chains(self, text: str) -> tuple[str, int]:
        def _r(m):
            parts = re.findall(r'const-string\s+[vp]\d+,\s*"([^"]*)"', m.group(0))
            return f'    # UNGUARD-DEOB: SB→"{"".join(parts)}"\n' + m.group(0)
        return self._SB_CHAIN_RE.subn(_r, text)

    def _annotate_xor(self, text: str) -> tuple[str, int]:
        n = 0
        def _r(m):
            nonlocal n
            body = m.group(0)
            if sum(1 for mk in self._XOR_MARKERS if mk in body) < 2:
                return body
            consts = [int(x,16) if x.startswith("0x") else int(x)
                      for x in re.findall(r"const(?:/\d+)?\s+[vp]\d+,\s*(0x[0-9a-f]+|-?\d+)", body)
                      if x]
            freq = defaultdict(int)
            for c in consts:
                b = c & 0xFF
                if 0x20 <= b <= 0x7E: freq[b] += 1
            key = f" key=0x{max(freq,key=freq.get):02x}" if freq else ""
            n += 1
            return f"    # UNGUARD-DEOB: XOR-decrypt stub{key}\n" + body
        t = re.sub(r"(\.method\b[^\n]*\)Ljava/lang/String;\n(?:(?!\.method\b).)*?\.end method)",
                   _r, text, flags=re.DOTALL)
        return t, n

    def _annotate_aes(self, text: str) -> tuple[str, int]:
        def _r(m):
            name = m.group(0).split('"')[1]
            return f'    # UNGUARD-DEOB: cipher init ({name})\n' + m.group(0)
        return self._AES_RE.subn(_r, text)

    def _annotate_native(self, text: str) -> tuple[str, int]:
        return self._NATIVE_RE.subn(
            lambda m: "    # UNGUARD-DEOB: native JNI decrypt stub\n" + m.group(0), text)

    def _annotate_strarray(self, text: str) -> tuple[str, int]:
        return self._STR_ARR_RE.subn(
            lambda m: "    # UNGUARD-DEOB: string-array table\n" + m.group(0), text)

# ──────────────────────────────────────────────────────────────────────────────
#  Framework / Engine Detector  (two-pass: ZIP + decompiled dir)
# ──────────────────────────────────────────────────────────────────────────────
class FrameworkDetector:
    """
    Two-pass detection to handle split APKs where native libs live in arch
    splits, not base.apk.

    Pass 1 – ZIP inspection:   fast, pre-decompile.
    Pass 2 – Decompiled scan:  reliable, post-apktool.
    Results merged and disambiguated (e.g. Unity Mono vs IL2CPP).
    """

    LIB_SIGS = [
        # Unity
        ("libil2cpp.so",        "unity_il2cpp"),
        ("libunity.so",         "unity"),
        ("libmono.so",          "unity_mono"),
        ("libmonobdwgc2.0.so",  "unity_mono"),
        ("libmonobdwgc-2.0.so", "unity_mono"),
        ("libmonosgen-2.0.so",  "unity_mono"),
        # Unreal
        ("libUnreal.so",        "unreal"),
        ("libUE4.so",           "unreal"),
        ("libUE5.so",           "unreal"),
        # Flutter
        ("libflutter.so",       "flutter"),
        ("libapp.so",           "flutter"),
        # Godot
        ("libgodot_android.so", "godot"),
        ("libgodot-prebuilt.so","godot"),
        # Cocos2d-x
        ("libcocos2dcpp.so",    "cocos2dx"),
        ("libcocos2d.so",       "cocos2dx"),
        ("libcocosplay.so",     "cocos2dx"),
        # libGDX
        ("libgdx.so",           "libgdx"),
        # React Native
        ("libreactnativejni.so","react_native"),
        ("libhermes.so",        "react_native"),
        ("libjscexecutor.so",   "react_native"),
        # Xamarin
        ("libmono-android.so",  "xamarin"),
        ("libxamarin-app.so",   "xamarin"),
        ("libxa-internal-api.so","xamarin"),
        # XLua / Lua
        ("libxlua.so",          "xlua"),
        ("liblua.so",           "lua"),
        # SDL2
        ("libSDL2.so",          "sdl2"),
    ]

    ASSET_SIGS = [
        ("assets/bin/Data/Managed",           "unity_mono"),
        ("assets/bin/Data/globalgamemanagers","unity"),
        ("assets/bin/Data/mainData",          "unity"),
        ("Metadata/global-metadata.dat",      "unity_il2cpp"),
        ("flutter_assets/",                   "flutter"),
        ("assets/index.android.bundle",       "react_native"),
        ("assets/main.jsbundle",              "react_native"),
        ("assets/android.pck",                "godot"),
        ("assets/UE4Game",                    "unreal"),
        ("assets/UnrealGame",                 "unreal"),
        ("assets/Paks",                       "unreal"),
        ("assemblies/Xamarin",                "xamarin"),
        ("assemblies/mscorlib.dll",           "xamarin"),
    ]

    SMALI_SIGS = [
        (r"Lcom/unity3d/player/UnityPlayer;",   "unity"),
        (r"Lcom/unity3d/ads/",                  "unity"),
        (r"Lcom/unity3d/purchasingcore/",       "unity"),
        (r"Lcom/epicgames/",                    "unreal"),
        (r"Lio/flutter/",                       "flutter"),
        (r"Ldev/flutter/",                      "flutter"),
        (r"Lcom/facebook/react/",               "react_native"),
        (r"Lcom/facebook/soloader/",            "react_native"),
        (r"Lmono/android/",                     "xamarin"),
        (r"Lxamarin/android/",                  "xamarin"),
        (r"Lorg/cocos2dx/",                     "cocos2dx"),
        (r"Lcom/badlogic/gdx/",                 "libgdx"),
        (r"Lxlua/",                             "xlua"),
        (r"Lcom/godot/",                        "godot"),
    ]

    FRAMEWORK_META = {
        "unity_il2cpp": {
            "label":    "Unity (IL2CPP)",
            "color":    C.G,
            "strategy": (
                "IL2CPP compiles C# to native ARM – game logic not smali-patchable. "
                "IAP/Integrity Java wrappers (com.unity3d.*) ARE patchable."
            ),
        },
        "unity_mono": {
            "label":    "Unity (Mono/C#)",
            "color":    C.G,
            "strategy": (
                "C# DLLs in assets/bin/Data/Managed/ – use dnSpy for game logic. "
                "IAP/Integrity Java wrappers ARE patchable via smali."
            ),
        },
        "unity": {
            "label":    "Unity (subtype pending)",
            "color":    C.G,
            "strategy": "Unity runtime found; IL2CPP vs Mono distinction requires decompiled dir.",
        },
        "unreal": {
            "label":    "Unreal Engine",
            "color":    C.Y,
            "strategy": "Game logic in libUE4/5.so – not smali-patchable. JNI bridge IS patchable.",
        },
        "flutter": {
            "label":    "Flutter / Dart",
            "color":    C.CY,
            "strategy": "Dart code in libapp.so – not smali-patchable. Platform channels ARE.",
        },
        "react_native": {
            "label":    "React Native",
            "color":    C.CY,
            "strategy": "JS in Hermes engine – not smali-patchable. Native modules ARE.",
        },
        "xamarin": {
            "label":    "Xamarin / .NET",
            "color":    C.M,
            "strategy": "C# in assemblies/*.dll – use dnSpy. Android wrappers ARE patchable.",
        },
        "cocos2dx": {
            "label":    "Cocos2d-x",
            "color":    C.B,
            "strategy": "C++ in libcocos2dcpp.so. Java JNI bridge IS patchable.",
        },
        "libgdx":  {"label":"libGDX",          "color":C.B,  "strategy":"Java-based. Fully smali-patchable."},
        "xlua":    {"label":"XLua/Lua",         "color":C.Y,  "strategy":"Lua + Unity. Java wrappers patchable."},
        "lua":     {"label":"Lua Runtime",      "color":C.Y,  "strategy":"Lua scripts. Java wrappers patchable."},
        "sdl2":    {"label":"SDL2",             "color":C.W,  "strategy":"C/C++ via SDL2. Java wrappers patchable."},
        "godot":   {"label":"Godot Engine",     "color":C.G,  "strategy":"GDScript/.pck. Java wrappers patchable."},
    }

    @classmethod
    def detect_from_zip(cls, apk_path: str) -> dict:
        found = defaultdict(list)
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                namelist = z.namelist()
        except Exception:
            return found
        for needle, fw in cls.LIB_SIGS:
            if any(needle in e for e in namelist):
                found[fw].append(f"[ZIP] {needle}")
        for needle, fw in cls.ASSET_SIGS:
            if any(needle in e for e in namelist):
                found[fw].append(f"[ZIP] {needle}")
        return found

    # Extra filesystem asset signatures (post-decompile only)
    ASSET_FS_EXTRA = [
        ("assets/res",              "cocos2dx"),
        ("assets/src",              "cocos2dx"),
        ("assets/node_modules",     "react_native"),
        ("assets/game.projectc",    "defold"),
        ("assets/game.darc",        "defold"),
        ("assets/main.lu",          "corona"),
        ("assets/resource.car",     "corona"),
        ("assets/Content",          "monogame"),
        ("META-INF/AIR",            "adobe_air"),
    ]
    _EXTRA_META = {
        "defold":    {"label":"Defold Engine",  "color":C.CY, "strategy":"Lua/C++. Java wrappers patchable."},
        "corona":    {"label":"Corona/Solar2D", "color":C.Y,  "strategy":"Lua. Java wrappers patchable."},
        "monogame":  {"label":"MonoGame/FNA",   "color":C.M,  "strategy":"C# XNA. Java wrappers patchable."},
        "adobe_air": {"label":"Adobe AIR",      "color":C.R,  "strategy":"AS3/AIR. Java wrappers patchable."},
    }

    @classmethod
    def detect_from_dir(cls, decomp_dir: str) -> dict:
        """
        Deep scan of decompiled directory.
        Sources: lib/ .so files | assets/ paths | AndroidManifest.xml | smali classes
        """
        found = defaultdict(list)
        base  = Path(decomp_dir)

        # 1. lib/ native library walk
        lib_dir = base / "lib"
        if lib_dir.is_dir():
            for so_path in lib_dir.rglob("*.so"):
                name = so_path.name
                for needle, fw in cls.LIB_SIGS:
                    if needle in name:
                        found[fw].append(f"[lib] {so_path.relative_to(base)}")
                        break

        # 2. assets/ path walk (all signatures)
        assets_dir = base / "assets"
        all_sigs   = cls.ASSET_SIGS + cls.ASSET_FS_EXTRA
        if assets_dir.is_dir():
            for ap in assets_dir.rglob("*"):
                rel_str = str(ap.relative_to(base)).replace(os.sep, "/")
                for needle, fw in all_sigs:
                    if needle in rel_str or needle in ap.name:
                        if f"[assets] {needle}" not in found[fw]:
                            found[fw].append(f"[assets] {needle}")
                        break

        # 3. AndroidManifest.xml parsing
        manifest = base / "AndroidManifest.xml"
        if manifest.is_file():
            try:
                mt = manifest.read_text(encoding="utf-8", errors="ignore")
                MANIFEST_SIGS = [
                    ("com.unity3d.player.UnityPlayerActivity",         "unity"),
                    ("com.unity3d.player.UnityPlayerGameActivity",     "unity"),
                    ("io.flutter.embedding.android.FlutterActivity",   "flutter"),
                    ("dev.flutter",                                     "flutter"),
                    ("com.facebook.react.ReactActivity",               "react_native"),
                    ("com.epicgames",                                   "unreal"),
                    ("GameActivity",                                    "unreal"),
                    ("org.godotengine",                                 "godot"),
                    ("mono.android.app.Application",                   "xamarin"),
                    ("com.adobe.air",                                   "adobe_air"),
                    ("org.cocos2dx",                                    "cocos2dx"),
                    ("com.badlogic.gdx",                                "libgdx"),
                ]
                for sig, fw in MANIFEST_SIGS:
                    if sig in mt:
                        found[fw].append(f"[manifest] {sig}")
            except Exception:
                pass

        # 4. Smali class scan (parallel, up to 3000 files)
        compiled   = [(re.compile(p, re.IGNORECASE), fw) for p, fw in cls.SMALI_SIGS]
        sm_lock    = threading.Lock()
        sm_found   = defaultdict(list)
        sm_seen    = set()
        sm_files   = list(base.rglob("*.smali"))[:3000]

        def _smali_check(sf):
            try:    text = sf.read_text(encoding="utf-8", errors="ignore")
            except: return
            for pat, fw in compiled:
                with sm_lock:
                    if fw in sm_seen: continue
                if pat.search(text):
                    with sm_lock:
                        sm_seen.add(fw)
                        sm_found[fw].append(f"[smali] {sf.name}")

        workers = min(MAX_WORKERS, 4)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_smali_check, sm_files))

        for fw, sigs in sm_found.items():
            found[fw].extend(sigs)

        # Register extra meta entries
        cls.FRAMEWORK_META.update(cls._EXTRA_META)
        return found

    @classmethod
    def _resolve(cls, raw: dict) -> dict:
        """Disambiguate Unity Mono vs IL2CPP; remove generic 'unity' if specific found."""
        resolved = dict(raw)
        # Merge: if both specific variants and generic "unity" key present
        if "unity" in resolved and ("unity_mono" in resolved or "unity_il2cpp" in resolved):
            extras = resolved.pop("unity", [])
            target = "unity_il2cpp" if "unity_il2cpp" in resolved else "unity_mono"
            resolved[target].extend(extras)
        elif "unity" in resolved:
            # Only generic – classify based on available signals
            sigs = " ".join(resolved["unity"])
            if "il2cpp" in sigs.lower() or "global-metadata" in sigs.lower():
                resolved["unity_il2cpp"] = resolved.pop("unity")
            else:
                resolved["unity_mono"] = resolved.pop("unity")
                resolved["unity_mono"].append("(no IL2CPP metadata found → classified as Mono)")
        # If both il2cpp and mono signals, merge under il2cpp (takes precedence)
        if "unity_il2cpp" in resolved and "unity_mono" in resolved:
            resolved["unity_il2cpp"].extend(resolved.pop("unity_mono"))
        return resolved

    @classmethod
    def print_report(cls, raw: dict):
        resolved = cls._resolve(dict(raw))
        if not resolved:
            log("ok", f"Framework: {C.BD}Native / Java{C.RS}")
            log("info", "Strategy: full smali patching available for all layers.", indent=1)
            return
        log("ok", f"Detected {len(resolved)} framework(s):")
        for fw, signals in resolved.items():
            meta   = cls.FRAMEWORK_META.get(fw, {"label":fw,"color":C.W,"strategy":"Java wrappers patchable."})
            unique = list(dict.fromkeys(signals))[:4]
            log("ok",   f"{meta['color']}{C.BD}{meta['label']}{C.RS}  "
                        f"[{', '.join(unique)}]", indent=1)
            log("info",  meta["strategy"], indent=2)

# ──────────────────────────────────────────────────────────────────────────────
#  Commercial Obfuscation Detector (uses shared cache)
# ──────────────────────────────────────────────────────────────────────────────
class CommercialObfuscationDetector:
    SIGS = {
        "dexguard":   [r"com/guardsquare",r"dexguard",r"com/saikoa/dexguard",
                       r"StringEncrypt",r"ResourceEncrypt",r"libdexguard"],
        "arxan":      [r"com/arxan",r"com/irdeto",r"com/verimatrix"],
        "dasho":      [r"com/preemptive/protection",r"com/dasho"],
        "appsealing": [r"com/inka/android/appsealing"],
        "bangcle":    [r"com/secshell",r"com/bangcle"],
        "ijiami":     [r"ijiami",r"com/ijm"],
        "jiagu360":   [r"com/qihoo/jiagu",r"com/360safe"],
        "liapp":      [r"com/infraware/liapp"],
        "tencent":    [r"com/tencent/bugly",r"legu"],
    }
    _DG_STUBS = [
        re.compile(r"\.method\s+(?:\S+\s+)*static\s+\S+\(I\)Ljava/lang/String;"),
        re.compile(r"\.method\s+(?:\S+\s+)*static\s+\S+\(II\)Ljava/lang/String;"),
        re.compile(r"\.method\s+(?:\S+\s+)*static\s+\S+\(J\)Ljava/lang/String;"),
    ]
    _DG_BODY = ["aget-byte","xor-int","ushr-int","array-length"]
    SCORE_MAP = {
        "dexguard":35,"dexguard_stubs":25,"arxan":40,"dasho":30,
        "appsealing":30,"bangcle":30,"ijiami":30,"jiagu360":30,
        "liapp":25,"tencent":10,"proguard_rename":15,"packer_native":20,
    }

    def __init__(self, cache: SmaliCache, target_apk: str, workers: int = MAX_WORKERS):
        self.cache   = cache
        self.target  = target_apk
        self.workers = workers
        self.found: dict[str, list] = defaultdict(list)
        self.score   = 0

    def detect(self) -> dict:
        log("head", "Commercial Obfuscation Detection")
        self._check_zip()
        items = list(self.cache.items())
        lock  = threading.Lock()

        compiled_sigs = {tool: [re.compile(p, re.I) for p in pats]
                         for tool, pats in self.SIGS.items()}

        def _scan(item):
            rel, text = item
            if not text: return {}
            local: dict[str, list[str]] = defaultdict(list)
            for tool, pats in compiled_sigs.items():
                for pat in pats:
                    if pat.search(text): local[tool].append(rel); break
            for sig_re in self._DG_STUBS:
                for m in sig_re.finditer(text):
                    end_idx = text.find(".end method", m.end())
                    if end_idx == -1: continue
                    body = text[m.end():end_idx]
                    if sum(1 for mk in self._DG_BODY if mk in body) >= 2:
                        local["dexguard_stubs"].append(rel); break
            return dict(local)

        total  = len(items)
        done_n = [0]
        pb     = Progress("Commercial scan", total) if total > 50 else None
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for local in ex.map(_scan, items):
                for k, v in local.items():
                    with lock: self.found[k].extend(v)
                done_n[0] += 1
                if pb and (done_n[0] % 100 == 0 or done_n[0] == total):
                    pb.update(done_n[0])
        if pb:
            pb.done()

        # Naming entropy
        files = list(self.cache.all_rels())
        short = sum(1 for r in files
                    if all(len(p) <= 2 for p in Path(r).with_suffix("").parts if p))
        ratio = short / max(len(files), 1)
        if ratio > 0.40:
            self.found["proguard_rename"].append(
                f"{short}/{len(files)} ({ratio:.0%}) files ≤2-char")

        for k in self.found: self.score += self.SCORE_MAP.get(k, 10)
        self.score = min(self.score, 100)

        if self.found:
            for tool, ev in self.found.items():
                log("detect", f"{C.BD}{tool.upper()}{C.RS}  ({len(ev)} hit(s))", indent=1)
            log("warn", f"Commercial obfuscation score: {C.BD}{self.score}/100{C.RS}")
        else:
            log("ok", "No commercial obfuscation fingerprints found.")
        return dict(self.found)

    def _check_zip(self):
        try:
            with zipfile.ZipFile(self.target, "r") as z:
                for name in z.namelist():
                    if re.search(r"libdexguard", name, re.I):
                        self.found["dexguard"].append(name)
                    if re.search(r"libprotect|libjiagu|libshell|libsecexe", name, re.I):
                        self.found["packer_native"].append(name)
        except Exception:
            pass

# ──────────────────────────────────────────────────────────────────────────────
#  Keystore manager – auto-create debug keystore when none exists
# ──────────────────────────────────────────────────────────────────────────────
class KeystoreManager:
    @staticmethod
    def ensure(keystore: str, alias: str, password: str) -> bool:
        """Return True if keystore is ready (exists or was created)."""
        if os.path.isfile(keystore):
            return True
        log("warn", f"Keystore '{keystore}' not found – auto-generating debug keystore…")
        try:
            cmd = [
                "keytool", "-genkey", "-v",
                "-keystore",   keystore,
                "-alias",      alias,
                "-keyalg",     "RSA",
                "-keysize",    "2048",
                "-validity",   "9125",    # 25 years
                "-storepass",  password,
                "-keypass",    password,
                "-dname",      "CN=UnGuard Debug, OU=Debug, O=UnGuard, L=Local, ST=State, C=US",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and os.path.isfile(keystore):
                log("ok", f"UnGuard debug keystore created: {keystore}")
                return True
            log("err", f"keytool failed: {r.stderr[:200]}")
        except FileNotFoundError:
            log("err", "keytool not found – is JDK installed?")
        except Exception as e:
            log("err", f"Keystore generation error: {e}")
        return False

# ──────────────────────────────────────────────────────────────────────────────
#  Main Patcher Orchestrator
# ──────────────────────────────────────────────────────────────────────────────
class AndroidPatcher:
    """
    Pipeline:
      1. handle_split_apk       – unwrap AAB/APKS if needed
      2. detect_engine          – Unity / Flutter / Unreal detection
      3. decompile              – apktool d (with --no-res fast path)
      4. analyze_with_androguard– package name, SDK, permissions
      5. SmaliCache.load()      – read all smali once into memory
      6. CommercialObfuscationDetector.detect()
      7. CustomObfuscationEngine.detect() + .deobfuscate()
      8. PatchEngine.find_all() – tag IAP / Integrity / Storage / Server files
      9. For each variant (parallel copytree+patch, sequential rebuild):
           a. copytree master → variant dir     (parallel, fast)
           b. patch_*() on variant dir           (parallel)
           c. apktool b rebuild                  (sequential, JVM-heavy)
           d. sign                               (parallel, light)
    """

    def __init__(self, target: str, output_dir: str = ".",
                 work_dir: str | None = None,
                 skip_sign: bool = False, skip_deob: bool = False,
                 workers: int = MAX_WORKERS):
        self.target     = os.path.abspath(target)
        self.output_dir = os.path.abspath(output_dir)
        self.work_dir   = work_dir or tempfile.mkdtemp(prefix="anapatch_")
        self.skip_sign  = skip_sign
        self.skip_deob  = skip_deob
        self.workers    = workers
        self.decompiled : str | None = None
        self.package    = "unknown"
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.work_dir,   exist_ok=True)

    # ── Pre-processing ────────────────────────────────────────────────────────
    def detect_engine(self):
        """Pass 1: ZIP inspection. Fast, pre-decompile."""
        log("info", "Detecting framework / engine (pass 1: ZIP)...")
        self._framework_info: dict = defaultdict(list)
        for fw, sigs in FrameworkDetector.detect_from_zip(self.target).items():
            self._framework_info[fw].extend(sigs)
        if self._framework_info:
            labels = [FrameworkDetector.FRAMEWORK_META.get(fw,{}).get("label",fw)
                      for fw in self._framework_info]
            log("info", f"ZIP signals: {C.BD}{', '.join(labels)}{C.RS} (confirming post-decompile)")
        else:
            log("info", "No framework signals in ZIP (may be split APK – will re-check post-decompile)")

    def detect_engine_post_decompile(self):
        """Pass 2: decompiled dir scan. Resolves split-APK blind-spot."""
        if not self.decompiled or not os.path.isdir(self.decompiled):
            FrameworkDetector.print_report(self._framework_info)
            return
        log("info", "Detecting framework / engine (pass 2: decompiled dir)...")
        for fw, sigs in FrameworkDetector.detect_from_dir(self.decompiled).items():
            self._framework_info[fw].extend(sigs)
        log("head", "Framework Detection Result")
        FrameworkDetector.print_report(self._framework_info)

    def handle_split_apk(self):
        """
        Normalise any archive format into a single APK apktool can handle.
          .apk  – pass through
          .aab  – Android App Bundle  → bundletool build-apks → extract
          .apks – bundletool zip       → extract base-master.apk
          .apkx – same as .apks
          .xapk – APKPure bundle       → extract largest inner APK
          .zip  – generic zip          → extract largest inner APK
        """
        ext = os.path.splitext(self.target)[1].lower()
        if ext == ".apk":
            return

        log("info", f"Archive format {ext.upper()} – extracting base APK…")

        if ext == ".aab":
            self._handle_aab(); return
        if ext in (".apks", ".apkx"):
            self._handle_apks_zip(self.target); return
        if ext == ".xapk":
            self._handle_xapk(); return
        if ext == ".zip":
            self._handle_generic_zip()

    def _handle_aab(self):
        apks_out = os.path.join(self.work_dir, "from_aab.apks")
        if os.path.isfile(BUNDLETOOL):
            log("info", "  bundletool build-apks --mode=universal…")
            cmd = [
                "java", "-jar", BUNDLETOOL, "build-apks",
                f"--bundle={self.target}",
                f"--output={apks_out}",
                "--mode=universal", "--overwrite",
            ]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if r.returncode == 0 and os.path.isfile(apks_out):
                    log("ok", "  bundletool OK")
                    base = self._extract_from_apks_zip(apks_out)
                    if base:
                        self.target = base
                        log("ok", f"  Base APK: {base}"); return
                else:
                    log("warn", f"  bundletool: {r.stderr.strip()[:200]}")
            except Exception as e:
                log("warn", f"  bundletool error: {e}")
        else:
            log("warn", f"  bundletool.jar not found at '{BUNDLETOOL}'")
            log("warn", "  Set BUNDLETOOL env-var or --bundletool flag.")
        log("warn", "  Trying apktool directly on AAB (may fail for complex bundles).")

    def _handle_apks_zip(self, zip_path: str):
        base = self._extract_from_apks_zip(zip_path)
        if base:
            self.target = base
            log("ok", f"  Base APK: {base}")
        else:
            log("warn", "  Could not locate base APK inside archive.")

    def _extract_from_apks_zip(self, zip_path: str):
        """
        Given a bundletool .apks ZIP, find the most complete single APK.
        Priority: universal.apk > splits/base-master.apk > base-master.apk > any .apk
        """
        out_dir = os.path.join(self.work_dir, "apks_ex")
        os.makedirs(out_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                nl = z.namelist()
                priority = [
                    "universal.apk", "splits/base-master.apk",
                    "base-master.apk", "base.apk",
                ]
                chosen = next((c for c in priority if c in nl), None)
                if not chosen:
                    # Fallback: biggest non-config APK
                    apks = [n for n in nl if n.endswith(".apk") and "config." not in n]
                    if apks:
                        chosen = max(apks, key=lambda n: z.getinfo(n).file_size)
                if not chosen:
                    return None
                dest = os.path.join(out_dir, os.path.basename(chosen))
                with z.open(chosen) as sf, open(dest, "wb") as df:
                    shutil.copyfileobj(sf, df)
                return dest
        except Exception as e:
            log("warn", f"  ZIP extraction error: {e}")
            return None

    def _handle_xapk(self):
        """XAPK: ZIP with top-level <pkg>.apk + manifest.json."""
        out_dir = os.path.join(self.work_dir, "xapk_ex")
        os.makedirs(out_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(self.target, "r") as z:
                nl     = z.namelist()
                # Prefer top-level APKs (not splits in subdirs)
                top    = [n for n in nl if n.endswith(".apk") and "/" not in n]
                others = [n for n in nl if n.endswith(".apk") and "/" in n]
                apks   = top if top else others
                if not apks:
                    log("warn", "  No APK found inside XAPK."); return
                best = max(apks, key=lambda n: z.getinfo(n).file_size)
                dest = os.path.join(out_dir, os.path.basename(best))
                with z.open(best) as sf, open(dest, "wb") as df:
                    shutil.copyfileobj(sf, df)
                self.target = dest
                log("ok", f"  XAPK base APK: {dest}")
        except Exception as e:
            log("warn", f"  XAPK extraction failed: {e}")

    def _handle_generic_zip(self):
        """Last resort: find any APK in a plain ZIP."""
        try:
            with zipfile.ZipFile(self.target, "r") as z:
                apks = [n for n in z.namelist() if n.endswith(".apk")]
                if not apks: return
                best = max(apks, key=lambda n: z.getinfo(n).file_size)
                dest = os.path.join(self.work_dir, os.path.basename(best))
                with z.open(best) as sf, open(dest, "wb") as df:
                    shutil.copyfileobj(sf, df)
                self.target = dest
                log("ok", f"  Extracted from ZIP: {dest}")
        except Exception as e:
            log("warn", f"  Generic ZIP failed: {e}")

    def analyze_with_androguard(self):
        if not _ANDROGUARD:
            log("warn","androguard not installed – run bash installer.sh"); return
        log("info","Androguard static analysis...")
        import io, warnings
        # Suppress androguard's "Requested API level X larger than maximum" stderr noise
        _old_stderr, sys.stderr = sys.stderr, io.StringIO()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                a = _ag_apk.APK(self.target)
            self.package = a.get_package()
            log("ok", f"Package : {C.BD}{self.package}{C.RS}")
            log("ok", f"SDK     : min={a.get_min_sdk_version()} "
                       f"target={a.get_target_sdk_version()}")
            log("ok", f"Perms   : {len(a.get_permissions())}")
        except Exception as e:
            log("warn", f"Androguard: {e}")
        finally:
            sys.stderr = _old_stderr

    def decompile(self) -> bool:
        self.decompiled = os.path.join(self.work_dir, "decompiled")
        fname = os.path.basename(self.target)
        log("info", f"Decompiling {fname} with apktool…")
        _stop  = threading.Event()
        _sp    = ["/-\\|"]
        def _spin():
            chars = list("/-\\|"); i = 0
            while not _stop.is_set():
                ts = time.strftime("%H:%M:%S")
                with _PLOCK:
                    sys.stdout.write(
                        f"\r{C.CY}{ts}{C.RS} {C.CY}[{chars[i%4]}]{C.RS}"
                        f" Decompiling {C.BD}{fname}{C.RS}…")
                    sys.stdout.flush()
                time.sleep(0.15); i += 1
        for extra in [["--no-res"], []]:
            t = threading.Thread(target=_spin, daemon=True); t.start()
            cmd = ["java", "-jar", APKTOOL_JAR, "d", self.target,
                   "-o", self.decompiled, "-f"] + extra
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                _stop.set(); t.join()
                with _PLOCK: sys.stdout.write("\r"+" "*82+"\r"); sys.stdout.flush()
                log("err", "apktool timed out (600s)."); return False
            except Exception as e:
                _stop.set(); t.join()
                with _PLOCK: sys.stdout.write("\r"+" "*82+"\r"); sys.stdout.flush()
                log("err", f"apktool error: {e}"); return False
            finally:
                _stop.set(); t.join()
                with _PLOCK: sys.stdout.write("\r"+" "*82+"\r"); sys.stdout.flush()
            if r.returncode == 0:
                log("ok", f"Decompiled to: {self.decompiled}"); return True
            log("warn", f"apktool ({' '.join(extra) or 'full'}): {r.stderr.strip()[:200]}")
        return False

    # ── Rebuild ───────────────────────────────────────────────────────────────
    def rebuild(self, vdir: str, label: str) -> str | None:
        out = os.path.join(self.work_dir, f"unsigned_{label}.apk")
        log("info", f"Rebuilding variant [{label}]…")
        _stop = threading.Event()
        def _spin():
            chars = list("/-\\|"); i = 0
            while not _stop.is_set():
                ts = time.strftime("%H:%M:%S")
                with _PLOCK:
                    sys.stdout.write(
                        f"\r{C.CY}{ts}{C.RS} {C.CY}[{chars[i%4]}]{C.RS}"
                        f" Building {C.BD}{label}{C.RS}…")
                    sys.stdout.flush()
                time.sleep(0.15); i += 1
        t = threading.Thread(target=_spin, daemon=True); t.start()
        cmd = ["java", "-jar", APKTOOL_JAR, "b", vdir, "-o", out]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            _stop.set(); t.join()
            with _PLOCK: sys.stdout.write("\r"+" "*82+"\r"); sys.stdout.flush()
            log("err", f"Rebuild [{label}] timed out."); return None
        finally:
            _stop.set(); t.join()
            with _PLOCK: sys.stdout.write("\r"+" "*82+"\r"); sys.stdout.flush()
        if r.returncode == 0:
            kb = os.path.getsize(out) // 1024 if os.path.exists(out) else 0
            log("ok", f"Unsigned [{label}]: {out} ({kb} KB)"); return out
        err_lines = [l for l in r.stderr.splitlines()
                     if "error" in l.lower() or "smali" in l.lower()][:4]
        log("err", f"Rebuild [{label}] failed:")
        for l in err_lines:
            log("err", l.strip(), indent=1)
        return None

    # ── Sign ──────────────────────────────────────────────────────────────────
    def sign(self, unsigned: str, label: str) -> str:
        if self.skip_sign:
            log("warn","Signing skipped."); return unsigned

        # Ensure we have a keystore (auto-create debug if needed)
        ks_ready = KeystoreManager.ensure(KEYSTORE, KEY_ALIAS, KEY_PASS)
        if not ks_ready:
            log("warn", "No keystore available – returning unsigned APK.")
            return unsigned

        signed = os.path.join(self.work_dir, f"signed_{label}.apk")
        log("info", f"Signing [{label}]…")

        # apksigner (preferred)
        try:
            cmd = [APKSIGNER, "sign",
                   "--ks", KEYSTORE, "--ks-key-alias", KEY_ALIAS,
                   "--ks-pass", f"pass:{KEY_PASS}",
                   "--out", signed, unsigned]
            subprocess.run(cmd, check=True, capture_output=True, timeout=120)
            log("ok", f"Signed (apksigner) [{label}]: {signed}")
            return signed
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            log("warn", f"apksigner failed ({type(e).__name__}) – trying jarsigner…")

        # jarsigner fallback
        aligned = os.path.join(self.work_dir, f"aligned_{label}.apk")
        try:
            subprocess.run([ZIPALIGN,"-v","-p","4", unsigned, aligned],
                           check=True, capture_output=True, timeout=120)
            subprocess.run(["jarsigner","-verbose",
                            "-sigalg","SHA1withRSA","-digestalg","SHA1",
                            "-keystore", KEYSTORE, "-storepass", KEY_PASS,
                            aligned, KEY_ALIAS],
                           check=True, capture_output=True, timeout=120)
            shutil.copy(aligned, signed)
            log("ok", f"Signed (jarsigner) [{label}]: {signed}")
            return signed
        except Exception as e:
            log("err", f"Signing failed [{label}]: {e}")
            return unsigned   # return unsigned so variant still has an output

    # ── Build: copy + patch (runs in its own thread) ─────────────────────────
    def _copy_and_patch(self, patches: frozenset,
                        master: PatchEngine) -> tuple[frozenset, str]:
        """
        Phase 1 (parallel-safe):
          1. Copy master decompiled tree into a variant-specific directory.
          2. Apply exactly the patch categories in `patches`.
        Returns (patches, vdir).
        """
        slug  = patches_to_slug(patches)
        label = patches_to_label(patches)
        log("var", f"Patching [{slug}]  –  {label}")
        vdir  = os.path.join(self.work_dir, f"var_{slug}")

        if os.path.exists(vdir):
            shutil.rmtree(vdir, ignore_errors=True)
        shutil.copytree(self.decompiled, vdir)

        vcache = SmaliCache(vdir)
        vcache.load(show_progress=False)

        eng      = PatchEngine(vdir, vcache, self.workers)
        eng._iap = master._iap.copy()
        eng._int = master._int.copy()
        eng._sto = master._sto.copy()
        eng._srv = master._srv.copy()
        eng._ads = master._ads.copy()

        if "iap"       in patches: eng.patch_iap()
        if "integrity" in patches: eng.patch_integrity()
        if "ads"       in patches: eng.patch_ads()
        if "storageIO" in patches: eng.patch_storage()
        if "serverIO"  in patches: eng.patch_server_replies()

        return patches, vdir

    def _rebuild_and_sign(self, patches: frozenset, vdir: str) -> str | None:
        """Phase 2 (sequential, JVM-heavy): rebuild + sign → final APK."""
        slug     = patches_to_slug(patches)
        unsigned = self.rebuild(vdir, slug)
        if not unsigned:
            return None
        src  = self.sign(unsigned, slug)
        base = os.path.splitext(os.path.basename(self.target))[0]
        final = os.path.join(self.output_dir, f"{base}_{slug}.apk")
        shutil.copy(src, final)
        log("ok", f"{C.BD}{C.G}Output: {final}{C.RS}")
        return final

    # ── Main run ──────────────────────────────────────────────────────────────
    def run(self, patches: frozenset | None = None,
            detect_only: bool = False) -> dict:
        """
        Full pipeline.

        patches : frozenset of patch category keys, e.g. frozenset({"iap","ads"})
                  Pass None to run detect-only without building anything.
        """
        banner()
        t0 = time.time()

        self.handle_split_apk()
        self.detect_engine()
        if not self.decompile():
            return {}
        self.detect_engine_post_decompile()
        self.analyze_with_androguard()

        log("head", "Smali Cache")
        cache = SmaliCache(self.decompiled)
        cache.load()

        log("head", "Obfuscation Analysis")
        _t1  = time.time()
        comm = CommercialObfuscationDetector(cache, self.target, self.workers)
        cust = CustomObfuscationEngine(cache, self.workers)
        comm.detect()
        cust.detect()
        obf_score = comm.score + cust.score
        log("ok", f"Obfuscation analysis: {time.time()-_t1:.1f}s  score={obf_score}/200")

        if not self.skip_deob and obf_score > 10:
            _t2 = time.time()
            log("info", f"Score {obf_score} > 10 – running deobfuscation…")
            cust.deobfuscate()
            cache.invalidate()
            cache.load(show_progress=False)
            log("ok", f"Deobfuscation pass: {time.time()-_t2:.1f}s")
        else:
            log("info", "Obfuscation score low or --no-deob – skipping.")

        log("head", "API Detection")
        master = PatchEngine(self.decompiled, cache, self.workers)
        master.find_all()

        if detect_only or patches is None:
            log("ok", f"Detect-only complete ({time.time()-t0:.1f}s)")
            return {"master": master}

        # ── Phase 1: copy + patch (ONE combined build) ────────────────────────
        log("head", f"Phase 1 – Copy & Patch  [{patches_to_slug(patches)}]")
        patched_dir: str | None = None
        try:
            _, patched_dir = self._copy_and_patch(patches, master)
        except Exception as e:
            log("err", f"Copy/patch failed: {e}")
            return {}

        # ── Phase 2: rebuild + sign ───────────────────────────────────────────
        log("head", "Phase 2 – Rebuild & Sign")
        final = self._rebuild_and_sign(patches, patched_dir)

        # ── Summary ───────────────────────────────────────────────────────────
        elapsed = time.time() - t0
        log("head", f"Build Summary  ({elapsed:.0f}s)")
        label = patches_to_label(patches)
        if final and os.path.exists(final):
            kb = os.path.getsize(final) // 1024
            print(f"  {C.BD}{C.G}[OK]{C.RS}  {label}")
            print(f"       {C.G}✓  {final}  ({kb} KB){C.RS}")
            log("ok", f"{C.BD}Build complete.{C.RS}")
        else:
            print(f"  {C.BD}{C.R}[FAILED]{C.RS}  {label}")
            print(f"       {C.R}✗  BUILD FAILED{C.RS}")
            log("warn", "Build failed.")
        return {"output": final}

    def cleanup(self):
        if self.work_dir and os.path.isdir(self.work_dir):
            if self.work_dir.startswith(tempfile.gettempdir()):
                shutil.rmtree(self.work_dir, ignore_errors=True)
                log("info","Temp workspace removed.")


# ──────────────────────────────────────────────────────────────────────────────
#  Smali-file patcher  (single / bulk .smali patch mode)
#
#  Usage: python unguard.py --smali-file a.smali,b.smali --patch iap,ads
#
#  For each input file:
#    1. Scan: report every detectable IAP/Integrity/Ads/Storage/Server pattern
#             found in the file, with line numbers and severity.
#    2. Patch: apply exactly the requested categories (same engine as APK mode).
#    3. Output: write <original_name>_patched.smali next to the input file
#               (or into --output dir if specified).
#    4. Diff summary: show how many lines changed per category.
#
#  No apktool / JDK / keystore needed – works on raw smali text only.
# ──────────────────────────────────────────────────────────────────────────────
class SmaliFilePatcher:
    """
    Standalone smali-file scan + patch tool.

    Accepts one or more .smali files, performs a deep pattern scan with
    annotated line-level findings, then applies the chosen patch categories
    and writes <name>_patched.smali alongside the original (or to --output).
    """

    # ── Pattern banks: (compiled_re, category, tag, description) ─────────────
    SCAN_PATTERNS: list[tuple] = []   # built lazily in __init__

    def __init__(self, patches: frozenset, output_dir: str | None = None):
        self.patches    = patches
        self.output_dir = output_dir
        self._build_scan_patterns()

    def _build_scan_patterns(self):
        """
        Build a unified list of (regex, category, short_tag, description)
        for line-level scanning / annotation.
        """
        def _p(raw, cat, tag, desc):
            return (re.compile(raw, re.IGNORECASE), cat, tag, desc)

        self.SCAN_PATTERNS = [
            # ── IAP ────────────────────────────────────────────────────────────
            _p(r"Lcom/android/billingclient/api/BillingClient;",
               "iap", "BILLING_CLIENT",      "Google Play BillingClient reference"),
            _p(r"->launchBillingFlow",
               "iap", "LAUNCH_BILLING",      "Initiates a billing flow"),
            _p(r"->acknowledgePurchase|->consumeAsync",
               "iap", "CONSUME_PURCHASE",    "Consumes / acknowledges a purchase"),
            _p(r"->queryProductDetailsAsync",
               "iap", "QUERY_PRODUCTS",      "Queries available products"),
            _p(r"Lcom/android/billingclient/api/Purchase;",
               "iap", "PURCHASE_OBJ",        "Purchase data object"),
            _p(r"Lcom/amazon/device/iap/",
               "iap", "AMAZON_IAP",          "Amazon In-App Purchasing SDK"),
            _p(r"Lcom/huawei/hms/iap/",
               "iap", "HUAWEI_IAP",          "Huawei IAP SDK"),
            _p(r"\.method.+(?:isPremium|isSubscribed|hasPurchased|isPurchased|"
               r"isPaid|isVip|isVIP|isPro|isMember|isEntitled|hasFullAccess)\(\)Z",
               "iap", "PREMIUM_GATE",        "Boolean premium/subscription gate method"),
            _p(r"\.method.+(?:purchase|buy|startPurchase|initPurchase|launchPurchase|"
               r"beginPurchase|triggerPurchase|buyProduct|orderProduct)\(",
               "iap", "PURCHASE_METHOD",     "Purchase trigger method"),
            _p(r"purchaseState|PURCHASE_STATE_PURCHASED",
               "iap", "PURCHASE_STATE",      "Purchase state field / constant"),

            # ── Integrity ──────────────────────────────────────────────────────
            _p(r"->requestIntegrityToken",
               "integrity", "INTEGRITY_TOKEN",   "Requests a Play Integrity token"),
            _p(r"Lcom/google/android/play/core/integrity/IntegrityManager;",
               "integrity", "INTEGRITY_MGR",     "Play Integrity manager"),
            _p(r"Lcom/google/android/play/core/integrity/StandardIntegrityManager;",
               "integrity", "STD_INTEGRITY",     "Standard Integrity manager"),
            _p(r"Lcom/google/android/gms/safetynet/SafetyNet;",
               "integrity", "SAFETYNET",         "SafetyNet API reference"),
            _p(r"->attest\(",
               "integrity", "SAFETYNET_ATTEST",  "SafetyNet attest call"),
            _p(r"Lcom/android/vending/licensing/LicenseChecker;",
               "integrity", "LVL_CHECKER",       "License Verification Library"),
            _p(r"->getPackageInfo.*signatures|->signatures",
               "integrity", "SIG_CHECK",         "Package signature check"),
            _p(r"->getInstallerPackageName",
               "integrity", "INSTALLER_CHECK",   "Installer package name check"),
            _p(r"\.method.+(?:checkAppIntegrity|verifySignature|checkSignature|"
               r"validateIntegrity|verifyInstall|verifyDevice)\(",
               "integrity", "INTEGRITY_METHOD",  "Custom integrity check method"),
            _p(r"\.method.+onFailure\(",
               "integrity", "ON_FAILURE",        "Failure callback (integrity/billing)"),

            # ── Ads ────────────────────────────────────────────────────────────
            _p(r"Lcom/google/android/gms/ads/",
               "ads", "ADMOB",                   "Google AdMob SDK"),
            _p(r"Lcom/facebook/ads/",
               "ads", "FB_AUDIENCE_NET",          "Facebook Audience Network"),
            _p(r"Lcom/unity3d/ads/|Lcom/unity3d/services/ads/",
               "ads", "UNITY_ADS",               "Unity Ads SDK"),
            _p(r"Lcom/applovin/",
               "ads", "APPLOVIN",                "AppLovin MAX SDK"),
            _p(r"Lcom/ironsource/|Lcom/supersonicads/",
               "ads", "IRONSOURCE",              "IronSource SDK"),
            _p(r"Lcom/mopub/",
               "ads", "MOPUB",                   "MoPub / Twitter Ads"),
            _p(r"Lcom/vungle/",
               "ads", "VUNGLE",                  "Vungle / Liftoff SDK"),
            _p(r"Lcom/inmobi/",
               "ads", "INMOBI",                  "InMobi SDK"),
            _p(r"Lcom/chartboost/",
               "ads", "CHARTBOOST",              "Chartboost SDK"),
            _p(r"Lcom/tapjoy/",
               "ads", "TAPJOY",                  "Tapjoy SDK"),
            _p(r"Lcom/bytedance/sdk/openadsdk/",
               "ads", "PANGLE",                  "Pangle / TikTok Ads SDK"),
            _p(r"->loadAd\(|->loadInterstitial\(|->loadRewardedAd\(",
               "ads", "AD_LOAD",                 "Ad load / fetch call"),
            _p(r"->showAd\(|->showInterstitial\(|->showRewarded\(|->showVideo\(",
               "ads", "AD_SHOW",                 "Ad display / show call"),
            _p(r"\.method.+(?:isLoaded|isReady|isInterstitialReady|isVideoReady)\(\)Z",
               "ads", "AD_READY_GATE",           "Ad availability gate method"),

            # ── Storage ────────────────────────────────────────────────────────
            _p(r"Landroid/content/SharedPreferences;->getBoolean\(",
               "storageIO", "SPREFS_BOOL",        "SharedPreferences boolean read"),
            _p(r"Landroid/content/SharedPreferences;->getInt\(",
               "storageIO", "SPREFS_INT",         "SharedPreferences int read"),
            _p(r"Landroid/database/Cursor;->getInt\(",
               "storageIO", "CURSOR_INT",         "SQLite Cursor int column read"),
            _p(r"Landroid/database/sqlite/SQLiteDatabase;->(?:rawQuery|query)\(",
               "storageIO", "SQLITE_QUERY",       "Raw SQLite query"),
            _p(r"Landroidx/room/RoomDatabase;",
               "storageIO", "ROOM_DB",            "Room Database reference"),
            _p(r"isPremium|isUnlocked|premium_user|has_purchased",
               "storageIO", "PREM_FLAG",          "Premium/unlock flag string"),

            # ── Server I/O ─────────────────────────────────────────────────────
            _p(r"Lorg/json/JSONObject;->(?:getInt|optInt)\(",
               "serverIO", "JSON_INT",            "JSON integer field read (status)"),
            _p(r"Lorg/json/JSONObject;->(?:getBoolean|optBoolean)\(",
               "serverIO", "JSON_BOOL",           "JSON boolean field read (success)"),
            _p(r"Lretrofit2/Response;->(?:code|isSuccessful)\(",
               "serverIO", "RETROFIT_RESP",       "Retrofit2 response check"),
            _p(r"Lokhttp3/Response;->(?:code|isSuccessful)\(",
               "serverIO", "OKHTTP_RESP",         "OkHttp response code check"),
            _p(r"Ljava/net/HttpURLConnection;->getResponseCode\(",
               "serverIO", "HTTP_RESP_CODE",      "HttpURLConnection response code"),
        ]

    # ── Public API ────────────────────────────────────────────────────────────
    def run(self, smali_paths: list[str]) -> dict:
        """
        Process every file in smali_paths.
        Returns {"results": [{file, findings, patches, output}], "ok": bool}
        """
        banner()
        log("head", f"Smali File Mode  –  {len(smali_paths)} file(s)")
        log("ok",   f"Patch selection : {C.BD}{patches_to_label(self.patches)}{C.RS}")

        all_ok  = True
        results = []
        for path in smali_paths:
            r = self._process_one(path)
            results.append(r)
            if not r["ok"]:
                all_ok = False

        self._print_summary(results)
        return {"results": results, "ok": all_ok}

    # ── Single file ───────────────────────────────────────────────────────────
    def _process_one(self, path: str) -> dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            log("err", f"File not found: {path}")
            return {"file": path, "ok": False, "findings": [], "patches": 0, "output": None}

        if not path.endswith(".smali"):
            log("warn", f"File does not end in .smali – processing anyway: {path}")

        fname = os.path.basename(path)
        log("head", f"Processing: {fname}")

        # ── 1. Read ───────────────────────────────────────────────────────────
        try:
            original = open(path, encoding="utf-8", errors="ignore").read()
        except Exception as e:
            log("err", f"Cannot read {fname}: {e}")
            return {"file": path, "ok": False, "findings": [], "patches": 0, "output": None}

        lines = original.splitlines()

        # ── 2. Scan ───────────────────────────────────────────────────────────
        findings = self._scan(lines, fname)
        self._print_findings(findings, fname)

        # ── 3. Patch (copy into temp dir so PatchEngine can address by rel) ───
        t0 = time.time()
        work = tempfile.mkdtemp(prefix="ug_smali_")
        try:
            rel  = fname
            dest = os.path.join(work, rel)
            shutil.copy2(path, dest)

            cache = SmaliCache(work)
            cache.load(show_progress=False)

            eng  = PatchEngine(work, cache, MAX_WORKERS)
            # Force the file into every category set regardless of content
            # (user explicitly chose to patch it)
            eng._iap = {rel}; eng._int = {rel}
            eng._sto = {rel}; eng._srv = {rel}; eng._ads = {rel}

            n_patches = 0
            if "iap"       in self.patches: n_patches += eng.patch_iap()
            if "integrity" in self.patches: n_patches += eng.patch_integrity()
            if "ads"       in self.patches: n_patches += eng.patch_ads()
            if "storageIO" in self.patches: n_patches += eng.patch_storage()
            if "serverIO"  in self.patches: n_patches += eng.patch_server_replies()

            patched_text = open(dest, encoding="utf-8").read()

        finally:
            shutil.rmtree(work, ignore_errors=True)

        # ── 4. Write output ───────────────────────────────────────────────────
        stem = os.path.splitext(fname)[0]
        out_name = f"{stem}_patched.smali"
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            out_path = os.path.join(self.output_dir, out_name)
        else:
            out_path = os.path.join(os.path.dirname(path), out_name)

        try:
            open(out_path, "w", encoding="utf-8").write(patched_text)
        except Exception as e:
            log("err", f"Cannot write output: {e}")
            return {"file": path, "ok": False, "findings": findings,
                    "patches": n_patches, "output": None}

        # ── 5. Diff stats ─────────────────────────────────────────────────────
        orig_lines    = original.splitlines()
        patched_lines = patched_text.splitlines()
        added   = sum(1 for l in patched_lines if l.strip().startswith("# UNGUARD"))
        removed = max(0, len(orig_lines) - len(patched_lines) + added)

        elapsed = time.time() - t0
        log("ok",  f"Output   : {C.BD}{out_path}{C.RS}")
        log("ok",  f"Patches  : {C.G}{n_patches}{C.RS} applied  "
                   f"(+{added} annotation lines)  {elapsed:.2f}s")

        return {"file": path, "ok": True, "findings": findings,
                "patches": n_patches, "output": out_path}

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _scan(self, lines: list[str], fname: str) -> list[dict]:
        """
        Scan every line and report pattern matches.
        Returns list of {lineno, category, tag, description, snippet}.
        """
        findings = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pat, cat, tag, desc in self.SCAN_PATTERNS:
                if pat.search(line):
                    findings.append({
                        "lineno":      lineno,
                        "category":    cat,
                        "tag":         tag,
                        "description": desc,
                        "snippet":     stripped[:100],
                    })
                    break   # one finding per line is enough
        return findings

    # ── Printing ──────────────────────────────────────────────────────────────
    def _print_findings(self, findings: list[dict], fname: str):
        if not findings:
            log("ok", f"No exploitable patterns found in {fname}.")
            return

        # Group by category
        by_cat: dict[str, list] = defaultdict(list)
        for f in findings:
            by_cat[f["category"]].append(f)

        CAT_COLOR = {
            "iap":       C.G,  "integrity": C.Y,  "ads":      C.CY,
            "storageIO": C.M,  "serverIO":  C.B,
        }
        total = len(findings)
        log("warn", f"Found {C.BD}{total}{C.RS} exploitable pattern(s) in {fname}:")
        print()

        for cat, items in sorted(by_cat.items()):
            color = CAT_COLOR.get(cat, C.W)
            hdr   = f"  {color}{C.BD}[{cat.upper():10s}]{C.RS}  {len(items)} finding(s)"
            print(hdr)
            for item in items:
                will_patch = ("*" if cat in self.patches else " ")
                patch_ind  = f"{C.G}[will patch]{C.RS}" if cat in self.patches                              else f"{C.Y}[not selected]{C.RS}"
                print(f"    {C.CY}L{item['lineno']:4d}{C.RS}  "
                      f"{color}{item['tag']:20s}{C.RS}  "
                      f"{patch_ind}  {item['description']}")
                print(f"         {C.BD}{item['snippet']}{C.RS}")
            print()

        not_selected = {c for c in by_cat if c not in self.patches}
        if not_selected:
            log("info", f"Categories with findings but NOT selected for patching: "
                        f"{C.BD}{', '.join(sorted(not_selected))}{C.RS}")
            log("info", "  Add them to --patch to include in output.")

    def _print_summary(self, results: list[dict]):
        log("head", "Smali File Mode – Summary")
        ok_count = sum(1 for r in results if r["ok"])
        for r in results:
            fname = os.path.basename(r["file"])
            nf    = len(r["findings"])
            np_   = r["patches"]
            if r["ok"]:
                out = r["output"] or "n/a"
                print(f"  {C.G}{C.BD}OK{C.RS}  {fname}")
                print(f"       findings={nf}  patches={np_}")
                print(f"       {C.G}→ {out}{C.RS}")
            else:
                print(f"  {C.R}{C.BD}FAIL{C.RS}  {fname}")
        print()
        log("ok", f"{ok_count}/{len(results)} files processed successfully.")


# ── Helper: resolve --smali-file argument ─────────────────────────────────────
def _resolve_smali_files(raw: str) -> list[str]:
    """
    Parse a comma-separated list of .smali file paths.
    Each entry may be a glob pattern.
    Returns a deduplicated, ordered list of existing .smali file paths.
    """
    import glob
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    result = []
    seen   = set()
    for tok in tokens:
        matches = glob.glob(tok, recursive=True)
        if not matches:
            # Treat as literal path even if not found – validation happens later
            matches = [tok]
        for m in sorted(matches):
            if m not in seen:
                seen.add(m)
                result.append(m)
    return result

# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    global APKTOOL_JAR, KEYSTORE, KEY_ALIAS, KEY_PASS, MAX_WORKERS

    cats = "  " + "\n  ".join(
        f"{C.BD}{k:12s}{C.RS} {v}" for k, v in PATCH_CATEGORIES.items()
    )

    parser = argparse.ArgumentParser(
        prog="unguard.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"{C.BD}UnGuard v1.0.0{C.RS} – Android APK Patcher\n\n"
            f"Modes:\n"
            f"  {C.BD}APK mode{C.RS}        Pass an APK/AAB/APKS file as positional argument.\n"
            f"  {C.BD}Smali mode{C.RS}      Use --smali-file to patch .smali files directly.\n\n"
            f"Patch categories:\n{cats}\n\n"
            f"  {C.BD}all{C.RS}           All of the above in one build\n\n"
            f"Combine with comma, pipe, or space: iap,integrity,ads"
        ),
        epilog=(
            "Env-vars: APKTOOL_JAR KEYSTORE KEY_ALIAS KEY_PASS\n"
            "          ZIPALIGN APKSIGNER BUNDLETOOL MAX_WORKERS\n\n"
            "APK mode examples:\n"
            "  python unguard.py app.apk --patch iap,integrity\n"
            "  python unguard.py app.apk --patch ads,iap,integrity\n"
            "  python unguard.py app.apk --patch all\n"
            "  python unguard.py app.apk --patch iap|ads\n"
            "  python unguard.py app.apk --detect-only\n"
            "  python unguard.py app.apk --patch iap --no-sign\n"
            "  python unguard.py app.apk --patch all -o ./out\n\n"
            "Smali file mode examples:\n"
            "  python unguard.py --smali-file BillingManager.smali --patch iap\n"
            "  python unguard.py --smali-file A.smali,B.smali,C.smali --patch all\n"
            "  python unguard.py --smali-file smali/*.smali --patch iap,ads\n"
            "  python unguard.py --smali-file Pay.smali --patch iap -o ./out\n"
        ),
    )

    # target is optional in smali-file mode
    parser.add_argument("target", nargs="?", default=None,
        help="APK / AAB / APKS / APKX / XAPK / ZIP file  (omit when using --smali-file)")

    pg = parser.add_argument_group("Patch selection")
    pg.add_argument(
        "--patch",
        metavar="CATS",
        default=None,
        help=(
            "Comma/pipe-separated patch categories.\n"
            "  iap, integrity, ads, storageIO, serverIO, all\n"
            "  Examples: --patch iap,integrity   --patch all   --patch iap|ads\n"
            "  Required unless --detect-only."
        ),
    )

    sf_group = parser.add_argument_group("Smali file mode  (no APK / apktool needed)")
    sf_group.add_argument(
        "--smali-file",
        metavar="FILES",
        default=None,
        dest="smali_file",
        help=(
            "One or more .smali files to scan and patch directly.\n"
            "  Comma-separated: --smali-file A.smali,B.smali\n"
            "  Glob patterns:   --smali-file smali/*.smali\n"
            "  Each file is scanned for exploitable patterns, patched according\n"
            "  to --patch, and saved as <name>_patched.smali."
        ),
    )

    og = parser.add_argument_group("Output")
    og.add_argument("-o","--output", default=None, metavar="DIR",
        help=(
            "Output directory.\n"
            "  APK mode:   patched APK written here (default: current dir)\n"
            "  Smali mode: _patched.smali files written here (default: same dir as input)"
        ))
    og.add_argument("--work-dir", default=None, metavar="DIR",
        help="Override temp workspace directory (APK mode only)")

    tp = parser.add_argument_group("Tool paths  (also via env-vars, APK mode only)")
    tp.add_argument("--apktool",    default=None, metavar="PATH",
        help="Path to apktool.jar  (env: APKTOOL_JAR)")
    tp.add_argument("--keystore",   default=None, metavar="FILE",
        help="Keystore file         (env: KEYSTORE)")
    tp.add_argument("--alias",      default=None, metavar="NAME",
        help="Key alias             (env: KEY_ALIAS)")
    tp.add_argument("--password",   default=None, metavar="PASS",
        help="Keystore password     (env: KEY_PASS)")
    tp.add_argument("--bundletool", default=None, metavar="PATH",
        help="bundletool.jar path   (env: BUNDLETOOL)")
    tp.add_argument("--workers",    default=None, type=int,
        help=f"Thread count          (env: MAX_WORKERS, default: {MAX_WORKERS})")

    fg = parser.add_argument_group("Flags")
    fg.add_argument("--no-sign",     action="store_true",
        help="Output unsigned APK (APK mode only)")
    fg.add_argument("--no-deob",     action="store_true",
        help="Skip deobfuscation pass (APK mode only)")
    fg.add_argument("--keep-work",   action="store_true",
        help="Keep temp workspace after build (APK mode, debugging)")
    fg.add_argument("--detect-only", action="store_true",
        help="Scan / analyse only – no patching, no build")

    args = parser.parse_args()

    # ── Apply global overrides ─────────────────────────────────────────────────
    if args.apktool:  APKTOOL_JAR = args.apktool
    if args.keystore: KEYSTORE    = args.keystore
    if args.alias:    KEY_ALIAS   = args.alias
    if args.password: KEY_PASS    = args.password
    if args.workers:  MAX_WORKERS = args.workers
    if args.bundletool:
        global BUNDLETOOL
        BUNDLETOOL = args.bundletool

    # ── Resolve --patch ────────────────────────────────────────────────────────
    patches: frozenset | None = None
    if args.patch:
        try:
            patches = parse_patches(args.patch)
        except ValueError as e:
            log("err", str(e))
            log("info", f"Valid: {', '.join(sorted(PATCH_CATEGORIES))}, all")
            sys.exit(1)
        if not patches:
            log("err", "--patch resolved to empty set."); sys.exit(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  SMALI FILE MODE
    # ══════════════════════════════════════════════════════════════════════════
    if args.smali_file:
        if not patches and not args.detect_only:
            parser.error(
                "--patch is required with --smali-file unless --detect-only.\n"
                "  Example: --smali-file MyFile.smali --patch iap,ads"
            )

        smali_paths = _resolve_smali_files(args.smali_file)
        if not smali_paths:
            log("err", "No files resolved from --smali-file argument.")
            sys.exit(1)

        # detect-only smali mode: scan without patching
        if args.detect_only:
            patches = frozenset()   # scan all, patch none

        log("ok", f"Smali file mode: {len(smali_paths)} file(s)")
        log("ok", f"Patch selection: {C.BD}{patches_to_label(patches) if patches else 'scan only'}{C.RS}")

        sfp = SmaliFilePatcher(
            patches    = patches,
            output_dir = args.output,
        )
        result = sfp.run(smali_paths)
        sys.exit(0 if result["ok"] else 1)

    # ══════════════════════════════════════════════════════════════════════════
    #  APK MODE
    # ══════════════════════════════════════════════════════════════════════════
    if not args.target:
        parser.error(
            "A target file is required in APK mode.\n"
            "  Example: python unguard.py app.apk --patch iap\n"
            "  For smali files: python unguard.py --smali-file File.smali --patch iap"
        )

    if not os.path.isfile(args.target):
        log("err", f"File not found: {args.target}")
        log("info", "Supported formats: .apk  .aab  .apks  .apkx  .xapk  .zip")
        sys.exit(1)

    if not args.detect_only and patches is None:
        parser.error(
            "--patch is required unless --detect-only is used.\n"
            "  Examples: --patch iap,integrity,ads   --patch all"
        )

    if patches:
        log("ok", f"Patch selection: {C.BD}{patches_to_label(patches)}{C.RS}")

    patcher = AndroidPatcher(
        target     = args.target,
        output_dir = args.output or ".",
        work_dir   = args.work_dir,
        skip_sign  = args.no_sign,
        skip_deob  = args.no_deob,
        workers    = MAX_WORKERS,
    )

    ok = False
    try:
        results = patcher.run(
            patches     = patches,
            detect_only = args.detect_only,
        )
        if args.detect_only:
            ok = bool(results)
        else:
            out = results.get("output")
            ok  = bool(out and os.path.exists(out))
    except KeyboardInterrupt:
        log("warn", "Interrupted.")
    finally:
        if not args.keep_work:
            patcher.cleanup()

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
