#!/usr/bin/env python3
# unguard.py
"""
UnGuard v3.0.0 – Hybrid Static + Runtime Analysis
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

Changes vs v2.0.0  (v3.0.0)
----------------------------
* RuntimeConfig: modular opt-in feature flags (--trace-runtime, --tls-intercept,
  --learn, --hybrid, --net-debug). Base pipeline completely unaffected when unused.
* InstrumentationInjector: writes UGBridge.smali + ConnThread into decompiled APK,
  hooks Activity/Fragment/Service lifecycle, injects OkHttp interceptor, bumps
  .locals safely for each injected hook.
* BridgeServer: TCP event receiver (newline-delimited JSON) – streams live from APK.
* BehaviorProfileDB: SQLite-backed profile recording all runtime events.
* LearningEngine: auto-discovers premium gates, analytics, storage tokens; generates
  override rules keyed by URL fingerprint.
* ReplayEngine: converts learned rules into additional static smali patches (hybrid mode).
* ExceptionAnalyzer: classifies runtime exceptions → TLS pinning / integrity / anti-debug;
  prints targeted patch suggestions inline.
* LiveConsole: colour-coded real-time event stream with per-tag stats.
* HybridEngine: orchestrates learn→patch pipeline; loads rules file for --hybrid runs.
* Network Security Config injection (--tls-intercept): trusts system + user CAs,
  disables cleartext restrictions, removes domain-level pinning declarations.
* _print_runtime_instructions: post-build ADB/proxy setup guidance.

Changes vs v1.0.0
-----------------
* Atomic smali writes via temp-file + os.replace (no corruption on interrupt)
* Fixed move-result tracker: skips .line / labels / blank lines between
  invoke and move-result (obfuscation-resilient)
* Register alias propagation: after injecting a const, follow move-vX,vY
  chains so aliased registers are also corrected
* SmaliCache: memory-usage estimation + configurable cap with lazy fallback
* Parallel file-level patching (ThreadPoolExecutor per category)
* Post-patch verification: confirms UNGUARD markers were written
* Signing: jarsigner fallback now uses SHA256withRSA + tool pre-check
* Framework detector: no hard file-cap on smali scan (with per-fw early stop)
* PatchReport: structured JSON-serialisable report (--report flag)
* Improved opaque-predicate removal (handles const/4 0x1 conditionals)
* More precise _INTEGRITY_RE to avoid matching unrelated onFailure methods
* macOS / Darwin detected as a valid POSIX environment
"""

from __future__ import annotations

import os, sys, re, json, shutil, zipfile, tempfile, threading, time
import subprocess, argparse
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
APKTOOL_JAR  = os.environ.get("APKTOOL_JAR",  "apktool.jar")
KEYSTORE     = os.environ.get("KEYSTORE",     "unguard_debug.keystore")
KEY_ALIAS    = os.environ.get("KEY_ALIAS",    "unguard")
KEY_PASS     = os.environ.get("KEY_PASS",     "unguard")
ZIPALIGN     = os.environ.get("ZIPALIGN",     "zipalign")
APKSIGNER    = os.environ.get("APKSIGNER",    "apksigner")
BUNDLETOOL   = os.environ.get("BUNDLETOOL",   "bundletool.jar")
TOOL_NAME    = "UnGuard"
TOOL_VERSION = "3.0.0"
MAX_WORKERS  = int(os.environ.get("MAX_WORKERS", str(min(os.cpu_count() or 4, 8))))
# SmaliCache memory cap in MB – files beyond this are read on-demand instead of cached
CACHE_MAX_MB = int(os.environ.get("CACHE_MAX_MB", "512"))

# ──────────────────────────────────────────────────────────────────────────────
#  Thread-safe logger
# ──────────────────────────────────────────────────────────────────────────────
_PLOCK = threading.Lock()

# ──────────────────────────────────────────────────────────────────────────────
#  Progress bar  (thread-safe, works alongside log())
# ──────────────────────────────────────────────────────────────────────────────
class Progress:
    """
    ASCII progress bar that overwrites the same terminal line.

    Fixes vs previous version:
    • Uses \\033[2K (ANSI erase-entire-line) before \\r so Termux doesn't
      scroll a new line on each redraw.
    • Heartbeat background thread redraws every 0.4 s so the bar always
      ticks even when individual work items are very slow – no more
      apparent hangs at 0%.
    • update() / inc() are now fully thread-safe without deadlock.
    """
    BAR_W = 36

    def __init__(self, label: str, total: int):
        self.label    = label
        self.total    = max(total, 1)
        self.current  = 0
        self._lock    = threading.Lock()
        self._done_ev = threading.Event()
        self._draw(0)
        # Heartbeat: redraws bar every 0.4 s regardless of work speed
        self._hb = threading.Thread(target=self._heartbeat, daemon=True)
        self._hb.start()

    def _heartbeat(self):
        while not self._done_ev.wait(timeout=0.4):
            with self._lock:
                n = self.current
            self._draw(n)

    def update(self, n: int):
        with self._lock:
            self.current = n
        self._draw(n)

    def inc(self):
        with self._lock:
            self.current += 1
            n = self.current
        self._draw(n)

    def done(self, msg: str = ""):
        self._done_ev.set()          # stop heartbeat
        self._hb.join(timeout=1.0)
        with _PLOCK:
            # \033[2K = erase entire line, then \r = go to column 0
            sys.stdout.write("\033[2K\r" + " " * 84 + "\033[2K\r")
            sys.stdout.flush()
        if msg:
            log("ok", msg)

    def _draw(self, n: int):
        pct    = min(n / self.total, 1.0)
        filled = int(self.BAR_W * pct)
        bar    = C.G + "█" * filled + C.CY + "░" * (self.BAR_W - filled) + C.RS
        ts     = time.strftime("%H:%M:%S")
        # \033[2K erases the whole line first so Termux won't scroll
        line   = (f"\033[2K\r{C.CY}{ts}{C.RS} {C.CY}[~]{C.RS} "
                  f"{self.label}  [{bar}] "
                  f"{C.BD}{n}/{self.total}{C.RS} ({pct:.0%})")
        with _PLOCK:
            sys.stdout.write(line)
            sys.stdout.flush()

# ──────────────────────────────────────────────────────────────────────────────
#  Logger
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
    "verify": lambda: f"{C.G}[✓]{C.RS}",
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
  |  UnGuard v3.0.0  Hybrid Analysis Framework                 |
  |  --patch all  --trace-runtime  --tls-intercept  --learn   |
  |  Unity  Unreal  Flutter  Native   Multi-threaded          |
  |  --hybrid  --net-debug  │  DexGuard  Arxan  DashO         |
  +============================================================+{C.RS}
  {C.CY}Started : {ts}   Workers : {MAX_WORKERS}{C.RS}
""")

# ──────────────────────────────────────────────────────────────────────────────
#  Structured patch report
# ──────────────────────────────────────────────────────────────────────────────
class PatchReport:
    """
    Accumulates results from all patch passes and exports structured JSON.
    Thread-safe via internal lock.
    """
    def __init__(self):
        self._lock   = threading.Lock()
        self._items: list[dict] = []   # {file, category, line, kind}
        self.counts: dict[str, int] = defaultdict(int)
        self.errors: list[str] = []

    def add(self, category: str, rel: str, line: int, kind: str):
        with self._lock:
            self._items.append({"category": category, "file": rel,
                                 "line": line, "kind": kind})
            self.counts[category] += 1

    def add_error(self, msg: str):
        with self._lock:
            self.errors.append(msg)

    def to_dict(self) -> dict:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "counts": dict(self.counts),
            "total_patches": sum(self.counts.values()),
            "errors": self.errors,
            "patches": self._items,
        }

    def save(self, path: str):
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2)
            log("ok", f"Patch report saved: {path}")
        except Exception as e:
            log("warn", f"Could not save report: {e}")

# Global report instance – populated throughout the run
_REPORT = PatchReport()

# ──────────────────────────────────────────────────────────────────────────────
#  Patch category system
# ──────────────────────────────────────────────────────────────────────────────
PATCH_CATEGORIES = {
    "iap":       "IAP (Google Play / Amazon / Huawei / premium gates)",
    "integrity": "Integrity (Play Integrity / SafetyNet / LVL / signatures)",
    "ads":       "Ads (AdMob / Facebook / Unity / AppLovin / IronSource / …)",
    "storageIO": "Storage I/O (SQLite / Room / SharedPreferences flags)",
    "serverIO":  "Server I/O (JSON status / Retrofit / OkHttp response codes)",
}
ALL_PATCHES = frozenset(PATCH_CATEGORIES.keys())

_PATCH_ALIASES = {k.lower(): k for k in PATCH_CATEGORIES}
_PATCH_ALIASES.update({
    "storage": "storageIO", "storageio": "storageIO",
    "server":  "serverIO",  "serverio":  "serverIO",
    "server_io": "serverIO","storage_io": "storageIO",
    "network": "serverIO",
})

def parse_patches(raw: str) -> frozenset:
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
    if patches == ALL_PATCHES:
        return "all"
    return "_".join(sorted(patches))

def patches_to_label(patches: frozenset) -> str:
    if patches == ALL_PATCHES:
        return "All patches (IAP + Integrity + Ads + Storage + Server)"
    return " + ".join(PATCH_CATEGORIES[p] for p in sorted(patches))

# ──────────────────────────────────────────────────────────────────────────────
#  Shared smali file cache
#  FIX: Added memory-usage estimation with configurable cap.
#       Files exceeding the cap are read on-demand (lazy) rather than cached.
#       Added per-file size accounting to avoid OOM on giant apps.
# ──────────────────────────────────────────────────────────────────────────────
class SmaliCache:
    """
    Loads *.smali files into memory up to CACHE_MAX_MB.
    Files beyond the cap are read on-demand; the cache transparently falls back.
    All engines share one load, avoiding repeated I/O.
    """
    def __init__(self, base: str):
        self.base  = Path(base)
        self._data: dict[str, str] = {}   # rel_path → content (cached)
        self._all_rels: list[str]  = []   # every rel_path (cached + uncached)
        self._loaded  = False
        self._mem_mb  = 0.0

    def load(self, show_progress: bool = True):
        if self._loaded:
            return
        t0 = time.time()
        all_files = []
        for root, _, files in os.walk(str(self.base)):
            for fname in files:
                if fname.endswith(".smali"):
                    all_files.append(os.path.join(root, fname))
        total   = len(all_files)
        cap_b   = CACHE_MAX_MB * 1024 * 1024
        used_b  = 0
        pb      = Progress("Loading smali", total) if show_progress and total > 50 else None
        capped  = 0
        for i, full in enumerate(all_files):
            rel = os.path.relpath(full, str(self.base))
            self._all_rels.append(rel)
            if used_b < cap_b:
                try:
                    content = Path(full).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    content = ""
                self._data[rel] = content
                used_b += len(content.encode("utf-8", errors="ignore"))
            else:
                capped += 1   # leave out of _data; get() will read on-demand
            # Update every 50 files (was 100 – more responsive feel)
            if pb and (i % 50 == 0 or i == total - 1):
                pb.update(i + 1)
        self._mem_mb = used_b / (1024 * 1024)
        if pb:
            pb.done(f"Loaded {total - capped}/{total} smali files "
                    f"({self._mem_mb:.0f} MB) in {time.time()-t0:.1f}s")
        else:
            log("ok", f"Loaded {total - capped}/{total} smali files "
                f"({self._mem_mb:.0f} MB) in {time.time()-t0:.1f}s")
        if capped:
            log("warn", f"{capped} files exceed cache cap ({CACHE_MAX_MB} MB) – "
                "reading on-demand.  Set CACHE_MAX_MB env-var to raise the limit.")
        self._loaded = True

    def invalidate(self):
        self._data.clear()
        self._all_rels.clear()
        self._loaded = False

    def items(self):
        """Yield (rel, text) for every smali file (cached + on-demand)."""
        for rel in self._all_rels:
            if rel in self._data:
                yield rel, self._data[rel]
            else:
                try:
                    text = (self.base / rel).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    text = ""
                yield rel, text

    def all_rels(self) -> list[str]:
        return list(self._all_rels)

    def get(self, rel: str) -> str:
        if rel in self._data:
            return self._data[rel]
        try:
            return (self.base / rel).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

# ──────────────────────────────────────────────────────────────────────────────
#  Parallel pattern scanner (uses cache)
# ──────────────────────────────────────────────────────────────────────────────
class SmaliScanner:
    def __init__(self, cache: SmaliCache, workers: int = MAX_WORKERS):
        self.cache   = cache
        self.workers = workers

    def scan(self, patterns: list[tuple[str,str]],
             label: str = "Scanning") -> dict[str, set[str]]:
        """
        Returns {tag: set(rel_path)}.
        Uses submit()+as_completed() so the progress bar advances the moment
        ANY file finishes – not in submission order. This eliminates the
        apparent hang when the first file in the list is very large (e.g.
        Unity IL2CPP generated smali with thousands of methods).
        """
        compiled = [(re.compile(p, re.IGNORECASE), t) for p, t in patterns]
        bucket   = defaultdict(set)
        lock     = threading.Lock()
        items    = list(self.cache.items())
        total    = len(items)
        pb       = Progress(label, total) if total > 50 else None
        done     = 0

        def _work(item):
            rel, text = item
            if not text:
                return []
            return [(t, rel) for pat, t in compiled if pat.search(text)]

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(_work, item): item for item in items}
            for fut in as_completed(futs):
                try:
                    hits = fut.result()
                except Exception:
                    hits = []
                for t, rel in hits:
                    with lock:
                        bucket[t].add(rel)
                done += 1
                # Update every 50 completions (more responsive than 100)
                if pb and (done % 50 == 0 or done == total):
                    pb.update(done)

        if pb:
            pb.done()
        return dict(bucket)

# ──────────────────────────────────────────────────────────────────────────────
#  Atomic file write helper
#  FIX: All smali writes now go through this helper.
#       Write to a sibling temp file then os.replace() – atomic on POSIX/Windows.
#       Interrupted writes no longer corrupt the original file.
# ──────────────────────────────────────────────────────────────────────────────
def _atomic_write(path: str, lines: list[str]) -> bool:
    """Write lines to path atomically.  Returns True on success."""
    dir_ = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".ug_tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
        except Exception:
            os.unlink(tmp)
            raise
        os.replace(tmp, path)   # atomic on POSIX; best-effort on Windows
        return True
    except Exception as e:
        log("warn", f"Atomic write failed for {path}: {e}")
        return False

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
    for j in range(start + 1, end):
        s = lines[j].strip()
        if s.startswith(".locals ") or s.startswith(".registers "):
            return lines[j]
    return None

def _max_reg_index(lines: list[str], start: int, end: int) -> int:
    highest = -1
    for j in range(start + 1, end):
        for m in re.finditer(r"\bv(\d+)\b", lines[j]):
            highest = max(highest, int(m.group(1)))
    return highest + 1

def _safe_replace_body(lines: list[str], start: int, end: int,
                       new_body: list[str], locals_n: int,
                       tag: str = "replaced") -> list[str]:
    locals_line  = f"    .locals {locals_n}\n"
    marker_line  = f"    # UNGUARD: {tag}\n"
    return (lines[:start+1] + [locals_line, marker_line]
            + new_body + [lines[end]] + lines[end+1:])

# ── FIX: Improved move-result finder ─────────────────────────────────────────
#  The original looked at a fixed 5-line window including non-instruction lines.
#  Obfuscators insert .line directives, labels, and blank lines between invoke
#  and move-result (all valid Dalvik).  We now skip those and look farther.
_NON_CODE_RE = re.compile(
    r"^\s*(?:#.*|\.line\s+\d+|:\w+.*)?$"   # blank, comment, .line N, :label
)

def _next_move_result_idx(lines: list[str], from_idx: int,
                           lookahead: int = 12) -> int | None:
    """
    Return the line index of the next move-result(-object|-wide) after from_idx,
    skipping blank lines, .line directives, and labels.
    FIX: window expanded to 12 and non-code lines skipped explicitly.
    """
    for j in range(from_idx + 1, min(from_idx + 1 + lookahead, len(lines))):
        s = lines[j].strip()
        if re.match(r"move-result(?:-object|-wide)?\s+[vp]\d+", s):
            return j
        # Stop if we hit another instruction that is not a non-code line
        if s and not _NON_CODE_RE.match(lines[j]):
            break
    return None

def _next_move_result(lines: list[str], from_idx: int,
                      lookahead: int = 12) -> str | None:
    """Return register name (e.g. 'v0') of the next move-result, or None."""
    j = _next_move_result_idx(lines, from_idx, lookahead)
    if j is None:
        return None
    m = re.match(r"[ \t]*move-result(?:-object|-wide)?\s+([vp]\d+)", lines[j])
    return m.group(1) if m else None

# ── FIX: Register alias propagation ──────────────────────────────────────────
#  After injecting `const/4 vX, 0x1`, follow subsequent `move vY, vX` chains
#  within the same method so aliased registers are also overwritten.
#  This handles obfuscated code that copies the return value before using it.
def _propagate_register_alias(lines: list[str], inject_idx: int,
                               source_reg: str, const_val: str,
                               method_end_idx: int) -> int:
    """
    From inject_idx forward until method_end_idx, find `move vY, source_reg`
    instructions and insert a matching `const/4 vY, const_val` after each.
    Returns count of additional propagations inserted.
    """
    added = 0
    i = inject_idx + 1
    alias_regs = {source_reg}
    while i < method_end_idx:
        s = lines[i].strip()
        # move vDest, vSrc  (any move variant except move-result)
        m = re.match(r"move(?:-object|-wide)?/?\S*\s+([vp]\d+),\s*([vp]\d+)", s)
        if m:
            dest, src = m.group(1), m.group(2)
            if src in alias_regs and dest not in alias_regs:
                alias_regs.add(dest)
                lines.insert(i + 1,
                    f"    const/4 {dest}, {const_val}  "
                    f"# UNGUARD: alias-propagated from {source_reg}\n")
                added += 1
                i += 2
                continue
        i += 1
    return added

# ──────────────────────────────────────────────────────────────────────────────
#  Patch verification helper
#  FIX: After writing a patched file, re-read it and count UNGUARD markers.
#       Logs a warning if no markers are found (silent patch failure detection).
# ──────────────────────────────────────────────────────────────────────────────
_UNGUARD_MARKER_RE = re.compile(r"#\s*UNGUARD", re.IGNORECASE)

def _verify_patch(path: str, expected_min: int = 1) -> bool:
    """Return True if the file contains at least expected_min UNGUARD markers."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        count = len(_UNGUARD_MARKER_RE.findall(text))
        if count < expected_min:
            log("warn", f"Patch verification FAILED – only {count} UNGUARD "
                f"marker(s) in {os.path.basename(path)} (expected ≥{expected_min})",
                indent=1)
            return False
        return True
    except Exception as e:
        log("warn", f"Patch verification read error: {e}", indent=1)
        return False

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
        (r"Lcom/google/android/gms/ads/",                                  "admob"),
        (r"Lcom/google/ads/",                                              "admob"),
        (r"->loadAd\(",                                                    "admob"),
        (r"->loadInterstitial\(",                                          "admob"),
        (r"Lcom/facebook/ads/",                                            "fb_ads"),
        (r"Lcom/facebook/audience_network/",                               "fb_ads"),
        (r"Lcom/unity3d/ads/",                                             "unity_ads"),
        (r"Lcom/unity3d/services/ads/",                                    "unity_ads"),
        (r"Lcom/applovin/",                                                "applovin"),
        (r"Lcom/adjust/sdk/",                                              "applovin"),
        (r"Lcom/ironsource/",                                              "ironsource"),
        (r"Lcom/supersonicads/",                                           "ironsource"),
        (r"Lcom/mopub/",                                                   "mopub"),
        (r"Lcom/vungle/",                                                  "vungle"),
        (r"Lcom/vungle/warren/",                                           "vungle"),
        (r"Lcom/inmobi/",                                                  "inmobi"),
        (r"Lcom/chartboost/",                                              "chartboost"),
        (r"Lcom/tapjoy/",                                                  "tapjoy"),
        (r"Lcom/bytedance/sdk/openadsdk/",                                 "pangle"),
        (r"Lcom/ss/android/ugc/aweme/",                                    "pangle"),
        (r"Lco/ogury/",                                                    "ogury"),
        (r"Lcom/fyber/",                                                   "fyber"),
        (r"Lcom/digitalturbine/",                                          "fyber"),
        (r"Lcom/snap/",                                                    "snap_ads"),
        (r"Lcom/liftoff/",                                                 "liftoff"),
        (r"AdView|AdRequest|AdListener|AdLoader|AdUnit",                   "generic_ad"),
        (r"->showAd\(|->showInterstitial\(|->showRewarded\(",           "generic_ad"),
        (r"->loadBannerAd\(|->loadRewardedAd\(|->loadNativeAd\(",      "generic_ad"),
    ]

    # ── Ads method-name regexes ────────────────────────────────────────────────
    _ADS_LOAD_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:loadAd|loadInterstitial|loadInterstitialAd|loadBannerAd|"
        r"loadRewardedAd|loadRewardedInterstitialAd|loadNativeAd|"
        r"loadNativeExpressAd|loadAppOpenAd|loadOfferWall|loadVideo|"
        r"fetchAd|fetchInterstitial|fetchBanner|requestAd|requestBanner|"
        r"preloadAd|preloadInterstitial|cacheInterstitial|cacheVideo|"
        r"prepareAd|prepareInterstitial|initAd|initBanner|initInterstitial)\("
    )
    _ADS_SHOW_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:showAd|showInterstitial|showInterstitialAd|showRewarded|"
        r"showRewardedAd|showRewardedInterstitialAd|showAppOpenAd|"
        r"showVideo|showOfferWall|show|displayAd|displayInterstitial|"
        r"presentAd|presentInterstitial|playVideo|playAd)\("
    )
    _ADS_READY_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:isAdLoaded|isLoaded|isReady|isInterstitialReady|isVideoReady|"
        r"isRewardedVideoReady|isOfferWallReady|isBannerLoaded|"
        r"isInitialized|isAdAvailable|hasAd|isAdReady)\(\)Z"
    )

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

    # FIX: Scoped integrity regex – requires class context before onFailure
    # to avoid matching unrelated listener/callback methods.
    _INTEGRITY_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:requestIntegrityToken|attest|checkLicense|verifySignature|"
        r"checkSignature|checkAppIntegrity|validateIntegrity|"
        r"handleIntegrityResult|processIntegrityToken|verifyInstall|"
        r"validateToken|verifyDevice)\("
    )
    # Separate regex for onFailure – requires integrity parent class context
    _INTEGRITY_ONFAILURE_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"onFailure\("
    )
    # Class-level context that qualifies onFailure as integrity-related
    _INTEGRITY_CLASS_CONTEXT_RE = re.compile(
        r"(?:IntegrityManager|SafetyNet|LicenseChecker|IntegrityToken|"
        r"LicenseValidator|checkIntegrity|onIntegrity)",
        re.IGNORECASE,
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
        # FIX: parallel file-level patching
        total = self._patch_parallel(self._iap, self._patch_iap_file, "iap")
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
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1, tag="iap:purchase-stub")
                patched += 1
                _REPORT.add("iap", rel, i, "purchase_method_stub")
                log("patch", f"IAP purchase  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)
                continue

            # ── Boolean gate: isPremium() → return true ───────────────────────
            if self._BOOL_GATE_RE.search(stripped):
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
                nb  = ["    const/4 v0, 0x1\n", "    return v0\n"]
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1, tag="iap:bool-gate→true")
                patched += 1
                _REPORT.add("iap", rel, i, "bool_gate_true")
                log("patch", f"IAP bool gate  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)
                continue

            # ── BillingResponseCode → 0 (OK) inline ──────────────────────────
            if ("BillingResult;->getResponseCode()I" in stripped
                    and "invoke-virtual" in stripped):
                end = _method_end(lines, i)
                j = _next_move_result_idx(lines, i)
                if j is not None:
                    m = re.match(r"([ \t]+)(move-result)\s+([vp]\d+)", lines[j])
                    if m:
                        reg = m.group(3)
                        inject_line = (f"    const/4 {reg}, 0x0"
                                       f"  # UNGUARD: BillingResponseCode=OK\n")
                        lines.insert(j + 1, inject_line)
                        if end is not None:
                            _propagate_register_alias(lines, j + 1, reg, "0x0", end + 1)
                        patched += 1
                        _REPORT.add("iap", rel, j, "billing_code_ok")
                        i = j + 2; continue

            i += 1

        if patched:
            _atomic_write(path, lines)
            _verify_patch(path, expected_min=patched)
        return patched

    @staticmethod
    def _iap_success_body(cb) -> list[str]:
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
        total = self._patch_parallel(self._int, self._patch_integrity_file, "integrity")
        log("ok",  f"Integrity: {C.G}{total}{C.RS} patches applied.")
        return total

    def _patch_integrity_file(self, rel: str) -> int:
        path = os.path.join(self.base, rel)
        try:    lines = open(path, encoding="utf-8").readlines()
        except: return 0
        patched = 0

        # Pre-scan class context for onFailure scope decision
        full_text = "".join(lines)
        is_integrity_class = bool(self._INTEGRITY_CLASS_CONTEXT_RE.search(full_text))

        i = 0
        while i < len(lines):
            stripped = lines[i].rstrip()

            # FIX: onFailure is only patched if class has integrity context
            is_on_failure = (self._INTEGRITY_ONFAILURE_RE.search(stripped)
                             and is_integrity_class)

            if self._INTEGRITY_RE.search(stripped) or is_on_failure:
                if any(m in stripped for m in (' abstract',' native',' bridge')):
                    i += 1; continue
                end = _method_end(lines, i)
                if end is None: i += 1; continue
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
                lines = _safe_replace_body(lines, i, end, nb, loc, tag="integrity:stub")
                patched += 1
                _REPORT.add("integrity", rel, i, "integrity_stub")
                log("patch", f"Integrity  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb)
                continue

            # Nop signature checks inline
            if "->signatures" in stripped or "->getInstallerPackageName" in stripped:
                lines[i] = f"    # UNGUARD-NOP: {stripped.strip()}\n"
                _REPORT.add("integrity", rel, i, "sig_check_nop")
                patched  += 1

            i += 1

        if patched:
            _atomic_write(path, lines)
            _verify_patch(path, expected_min=patched)
        return patched

    # ── Storage patching ──────────────────────────────────────────────────────
    def patch_storage(self) -> int:
        if not self._sto:
            log("warn", "No storage files – skip."); return 0
        log("info", f"Patching storage ({len(self._sto)} files)…")
        total = self._patch_parallel(self._sto, self._patch_storage_file, "storageIO")
        log("ok",  f"Storage: {C.G}{total}{C.RS} patches applied.")
        return total

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
                reg = _next_move_result(lines, i)
                if reg:
                    j = _next_move_result_idx(lines, i)
                    end = _method_end(lines, i)
                    inject = f"    const/4 {reg}, 0x1  # UNGUARD: getBoolean=true\n"
                    lines.insert(j + 1, inject)
                    if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                    _REPORT.add("storageIO", rel, j, "sprefs_bool_true")
                    n_tot += 1; i = j + 2; continue

            # SharedPreferences.getInt near a premium key → force 1
            if ("SharedPreferences;->getInt" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=6):
                    reg = _next_move_result(lines, i)
                    if reg:
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        inject = f"    const/4 {reg}, 0x1  # UNGUARD: getInt(prem)=1\n"
                        lines.insert(j + 1, inject)
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("storageIO", rel, j, "sprefs_int_one")
                        n_tot += 1; i = j + 2; continue

            # Cursor.getInt near a premium key → force 1
            if ("Cursor;->getInt(" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=8):
                    reg = _next_move_result(lines, i)
                    if reg:
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        inject = f"    const/4 {reg}, 0x1  # UNGUARD: cursor.getInt(prem)=1\n"
                        lines.insert(j + 1, inject)
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("storageIO", rel, j, "cursor_int_one")
                        n_tot += 1; i = j + 2; continue

            # Room DAO premium/status query → force 1
            if ("Dao;->" in s and "invoke-interface" in s and
                    re.search(r"->(?:isPremium|isUnlocked|getStatus|getSubscription)\(\)", s)):
                reg = _next_move_result(lines, i)
                if reg:
                    j = _next_move_result_idx(lines, i)
                    end = _method_end(lines, i)
                    inject = f"    const/4 {reg}, 0x1  # UNGUARD: Room DAO prem=1\n"
                    lines.insert(j + 1, inject)
                    if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                    _REPORT.add("storageIO", rel, j, "room_dao_one")
                    n_tot += 1; i = j + 2; continue

            i += 1

        if n_tot:
            _atomic_write(path, lines)
            log("patch", f"Storage  {rel}  ({n_tot}x)", indent=1)
            _verify_patch(path, expected_min=n_tot)
        return n_tot

    def _near_prem_key(self, lines, idx, lookback=6) -> bool:
        start = max(0, idx - lookback)
        if self._PREM_KEYS.search("".join(lines[start:idx+1])): return True
        ms = idx
        while ms > 0 and not lines[ms].strip().startswith('.method'): ms -= 1
        me = idx + 1
        while me < len(lines) and not lines[me].strip().startswith('.end method'): me += 1
        return bool(self._PREM_KEYS.search("".join(lines[ms:me+1])))

    # ── Server-reply patching ─────────────────────────────────────────────────
    def patch_server_replies(self) -> int:
        if not self._srv:
            log("warn", "No server-reply files – skip."); return 0
        log("info", f"Patching server replies ({len(self._srv)} files)…")
        total = self._patch_parallel(self._srv, self._patch_server_file, "serverIO")
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
                    reg = _next_move_result(lines, i)
                    if reg:
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSON int=1\n")
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("serverIO", rel, j, "json_int_one")
                        n_tot += 1; i = j + 2; continue

            # JSONObject.getBoolean/optBoolean near status/success key → force true
            if ("JSONObject;->getBoolean(" in s or "JSONObject;->optBoolean(" in s):
                if self._near_status_key(lines, i, lookback=5):
                    reg = _next_move_result(lines, i)
                    if reg:
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSON bool=true\n")
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("serverIO", rel, j, "json_bool_true")
                        n_tot += 1; i = j + 2; continue

            # Retrofit2 / OkHttp .code() → 200
            if (("retrofit2/Response;->code()" in s or
                 "okhttp3/Response;->code()" in s) and "invoke-virtual" in s):
                reg = _next_move_result(lines, i)
                if reg:
                    j = _next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    _REPORT.add("serverIO", rel, j, "http_code_200")
                    n_tot += 1; i = j + 2; continue

            # Retrofit2 / OkHttp .isSuccessful() → true
            if (("retrofit2/Response;->isSuccessful()" in s or
                 "okhttp3/Response;->isSuccessful()" in s) and "invoke-virtual" in s):
                reg = _next_move_result(lines, i)
                if reg:
                    j = _next_move_result_idx(lines, i)
                    end = _method_end(lines, i)
                    lines.insert(j + 1,
                        f"    const/4 {reg}, 0x1  # UNGUARD: isSuccessful=true\n")
                    if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                    _REPORT.add("serverIO", rel, j, "is_successful_true")
                    n_tot += 1; i = j + 2; continue

            # HttpURLConnection.getResponseCode() → 200
            if ("HttpURLConnection;->getResponseCode()" in s and "invoke-virtual" in s):
                reg = _next_move_result(lines, i)
                if reg:
                    j = _next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    _REPORT.add("serverIO", rel, j, "http_url_200")
                    n_tot += 1; i = j + 2; continue

            # JSONArray.length() near status context → force 1 (non-empty)
            if ("JSONArray;->length()" in s and "invoke-virtual" in s):
                if self._near_status_key(lines, i, lookback=8):
                    reg = _next_move_result(lines, i)
                    if reg:
                        j = _next_move_result_idx(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSONArray.length=1\n")
                        _REPORT.add("serverIO", rel, j, "json_array_len_one")
                        n_tot += 1; i = j + 2; continue

            i += 1

        if n_tot:
            _atomic_write(path, lines)
            log("patch", f"Server  {rel}  ({n_tot}x)", indent=1)
            _verify_patch(path, expected_min=n_tot)
        return n_tot

    def _near_status_key(self, lines, idx, lookback=5) -> bool:
        start = max(0, idx - lookback)
        if self._STATUS_KEYS.search("".join(lines[start:idx+1])): return True
        ms = idx
        while ms > 0 and not lines[ms].strip().startswith('.method'): ms -= 1
        me = idx + 1
        while me < len(lines) and not lines[me].strip().startswith('.end method'): me += 1
        return bool(self._STATUS_KEYS.search("".join(lines[ms:me+1])))

    # ── Ads patching ──────────────────────────────────────────────────────────
    def patch_ads(self) -> int:
        if not self._ads:
            log("warn", "No ad SDK files – skip."); return 0
        log("info", f"Patching ads ({len(self._ads)} files)…")
        total = self._patch_parallel(self._ads, self._patch_ads_file, "ads")
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
                lines = _safe_replace_body(lines, i, end, nb, locals_n=0, tag="ads:load-nop")
                _REPORT.add("ads", rel, i, "load_nop")
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
                lines = _safe_replace_body(lines, i, end, nb, locals_n=0, tag="ads:show-nop")
                _REPORT.add("ads", rel, i, "show_nop")
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
                lines = _safe_replace_body(lines, i, end, nb, locals_n=1, tag="ads:ready→false")
                _REPORT.add("ads", rel, i, "ready_false")
                patched += 1
                log("patch", f"Ads isReady→false  {rel}  L{i}", indent=1)
                i += 1 + 1 + len(nb); continue

            # ── Inline nop: direct SDK load/show invoke calls ─────────────────
            s = stripped
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
            if (any(sig in s for sig in _AD_LOAD_INVOKE) and "invoke-" in s):
                lines[i] = f"    # UNGUARD-ADS: load nop'd: {stripped.strip()}\n"
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines) and re.match(r"[ \t]+move-result(?:-object|-wide)?\s", lines[j]):
                    lines[j] = "    # UNGUARD-ADS: move-result nop'd\n"
                    patched += 1
                _REPORT.add("ads", rel, i, "inline_load_nop")
                patched += 1
                i += 1; continue

            if (any(sig in s for sig in _AD_SHOW_INVOKE) and "invoke-" in s):
                lines[i] = f"    # UNGUARD-ADS: show nop'd: {stripped.strip()}\n"
                _REPORT.add("ads", rel, i, "inline_show_nop")
                patched += 1
                i += 1; continue

            i += 1

        if patched:
            _atomic_write(path, lines)
        return patched

    # ── FIX: Parallel file-level patching ─────────────────────────────────────
    def _patch_parallel(self, file_set: set[str],
                        patch_fn, category: str) -> int:
        """Run patch_fn(rel) on every file in file_set using a thread pool."""
        files  = list(file_set)
        totals = [0]
        lock   = threading.Lock()

        def _do(rel):
            n = patch_fn(rel)
            with lock:
                totals[0] += n

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            list(ex.map(_do, files))
        return totals[0]

# ──────────────────────────────────────────────────────────────────────────────
#  Custom Obfuscation Engine (uses shared cache)
# ──────────────────────────────────────────────────────────────────────────────
class CustomObfuscationEngine:
    _XOR_MARKERS  = frozenset(["xor-int","aget-byte","aput-byte",
                                "array-length","ushr-int/lit8","and-int/lit8"])
    _AES_RE       = re.compile(r'const-string\s+[vp]\d+,\s*"(?:AES|DES|Blowfish|RC4)[^"]*"', re.I)
    _NATIVE_RE    = re.compile(r"\.method\s+(?:\S+\s+)*native\s+\S+\([^)]*\)Ljava/lang/String;")
    _PACKER_RE    = re.compile(r"Ldalvik/system/(?:Dex|Path|InMemoryDex)ClassLoader;", re.I)
    _STR_ARR_RE   = re.compile(r"(?:[ \t]+const-string\s+[vp]\d+,\s*\"[^\"\n]{0,128}\"\n){5,}", re.M)
    _REFLECT_RE   = re.compile(r"Ljava/lang/reflect/Method;->invoke\("
                               r"|Ljava/lang/Class;->(?:getDeclared)?Method\(", re.I)

    # FIX: Improved opaque predicate detection – handles both 0x0 AND 0x1 seeds
    _OPAQUE_RE    = re.compile(
        r"([ \t]+const(?:/4|/16)?\s+(?P<r>[vp]\d+),\s*(?P<v>0x0|0x1|0|1)\n)"
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
        pb     = Progress("Obfuscation scan", total) if total > 50 else None
        done   = 0
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(_scan, item): item for item in items}
            for fut in as_completed(futs):
                try:
                    h = fut.result()
                except Exception:
                    h = {}
                for k, v in h.items():
                    counts[k] += v
                done += 1
                if pb and (done % 50 == 0 or done == total):
                    pb.update(done)
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

            text, n = self._remove_opaques(text);      count += n
            text, n = self._collapse_dead_gotos(text);  count += n
            text, n = self._annotate_sb_chains(text);   count += n
            text, n = self._annotate_xor(text);         count += n
            text, n = self._annotate_aes(text);         count += n
            text, n = self._annotate_native(text);      count += n
            text, n = self._annotate_strarray(text);    count += n

            if text != orig:
                path = self.cache.base / rel
                try:
                    # FIX: atomic write in deobfuscation too
                    dir_ = str(path.parent)
                    import tempfile as _tf
                    fd, tmp = _tf.mkstemp(dir=dir_, suffix=".ug_tmp")
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as fh:
                            fh.write(text)
                    except Exception:
                        os.unlink(tmp)
                        raise
                    os.replace(tmp, str(path))
                except Exception:
                    return 0
            return count

        items  = list(self.cache.items())
        count  = len(items)
        pb     = Progress("Deobfuscating", count) if count > 50 else None
        done   = 0
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(_deob, item): item for item in items}
            for fut in as_completed(futs):
                try:
                    total += fut.result()
                except Exception:
                    pass
                done += 1
                if pb and (done % 50 == 0 or done == count):
                    pb.update(done)
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
        """
        FIX: Handles both 0x0 (zero) and 0x1 (one) constant seeds.
        Truth table for zero: eqz/lez/gez → always taken; nez/ltz/gtz → never
        Truth table for one:  gtz/gez/nez → always taken; ltz/lez/eqz → never
        """
        n = 0
        def _r(m):
            nonlocal n
            val = m.group("v"); op = m.group("op"); lbl = m.group("lbl")
            zero = val in ("0x0", "0")
            one  = val in ("0x1", "1")
            # (op, is_zero) → always_taken
            TAKEN_ZERO = {"eqz", "lez", "gez"}
            NEVER_ZERO = {"nez", "gtz", "ltz"}
            # (op, is_one)  → always_taken
            TAKEN_ONE  = {"nez", "gtz", "gez"}
            NEVER_ONE  = {"eqz", "ltz", "lez"}

            always = (zero and op in TAKEN_ZERO) or (one and op in TAKEN_ONE)
            never  = (zero and op in NEVER_ZERO) or (one and op in NEVER_ONE)

            if always:
                n += 1
                return (f"    # UNGUARD-DEOB: opaque({val})→always-taken\n"
                        f"    goto :{lbl}\n")
            if never:
                n += 1
                return f"    # UNGUARD-DEOB: opaque({val})→never-taken\n"
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
#  Framework / Engine Detector
# ──────────────────────────────────────────────────────────────────────────────
class FrameworkDetector:
    LIB_SIGS = [
        ("libil2cpp.so",        "unity_il2cpp"),
        ("libunity.so",         "unity"),
        ("libmono.so",          "unity_mono"),
        ("libmonobdwgc2.0.so",  "unity_mono"),
        ("libmonobdwgc-2.0.so", "unity_mono"),
        ("libmonosgen-2.0.so",  "unity_mono"),
        ("libUnreal.so",        "unreal"),
        ("libUE4.so",           "unreal"),
        ("libUE5.so",           "unreal"),
        ("libflutter.so",       "flutter"),
        ("libapp.so",           "flutter"),
        ("libgodot_android.so", "godot"),
        ("libgodot-prebuilt.so","godot"),
        ("libcocos2dcpp.so",    "cocos2dx"),
        ("libcocos2d.so",       "cocos2dx"),
        ("libcocosplay.so",     "cocos2dx"),
        ("libgdx.so",           "libgdx"),
        ("libreactnativejni.so","react_native"),
        ("libhermes.so",        "react_native"),
        ("libjscexecutor.so",   "react_native"),
        ("libmono-android.so",  "xamarin"),
        ("libxamarin-app.so",   "xamarin"),
        ("libxa-internal-api.so","xamarin"),
        ("libxlua.so",          "xlua"),
        ("liblua.so",           "lua"),
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

        # 2. assets/ path walk
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

        # 4. FIX: Smali class scan – no hard file cap; per-framework early stop
        #    so we avoid scanning 50k files once all frameworks are identified.
        compiled   = [(re.compile(p, re.IGNORECASE), fw) for p, fw in cls.SMALI_SIGS]
        sm_lock    = threading.Lock()
        sm_found   = defaultdict(list)
        sm_seen: set[str] = set()
        # Collect all smali files from ALL smali dirs (handles multi-dex)
        sm_files: list[Path] = []
        for smali_dir in base.glob("smali*"):
            if smali_dir.is_dir():
                sm_files.extend(smali_dir.rglob("*.smali"))
        if not sm_files:
            sm_files = list(base.rglob("*.smali"))

        all_fw = {fw for _, fw in cls.SMALI_SIGS}

        def _smali_check(sf: Path):
            # Fast exit if all frameworks already found
            with sm_lock:
                if sm_seen >= all_fw:
                    return
            try:    text = sf.read_text(encoding="utf-8", errors="ignore")
            except: return
            for pat, fw in compiled:
                with sm_lock:
                    if fw in sm_seen:
                        continue
                if pat.search(text):
                    with sm_lock:
                        sm_seen.add(fw)
                        sm_found[fw].append(f"[smali] {sf.name}")

        workers = min(MAX_WORKERS, 4)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_smali_check, sm_files))

        for fw, sigs in sm_found.items():
            found[fw].extend(sigs)

        cls.FRAMEWORK_META.update(cls._EXTRA_META)
        return found

    @classmethod
    def _resolve(cls, raw: dict) -> dict:
        resolved = dict(raw)
        if "unity" in resolved and ("unity_mono" in resolved or "unity_il2cpp" in resolved):
            extras = resolved.pop("unity", [])
            target = "unity_il2cpp" if "unity_il2cpp" in resolved else "unity_mono"
            resolved[target].extend(extras)
        elif "unity" in resolved:
            sigs = " ".join(resolved["unity"])
            if "il2cpp" in sigs.lower() or "global-metadata" in sigs.lower():
                resolved["unity_il2cpp"] = resolved.pop("unity")
            else:
                resolved["unity_mono"] = resolved.pop("unity")
                resolved["unity_mono"].append("(no IL2CPP metadata found → classified as Mono)")
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
#  Commercial Obfuscation Detector
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
    # Fixed: replaced (?:\S+\s+)* with enumerated optional modifiers.
    # The old pattern caused catastrophic backtracking on large IL2CPP smali files
    # (thousands of static methods per file, hundreds of backtrack paths each).
    _DG_STUBS = [
        re.compile(r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|bridge|varargs)\s+)*static\s+\S+\(I\)Ljava/lang/String;"),
        re.compile(r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|bridge|varargs)\s+)*static\s+\S+\(II\)Ljava/lang/String;"),
        re.compile(r"\.method\s+(?:(?:public|private|protected|static|final|synthetic|bridge|varargs)\s+)*static\s+\S+\(J\)Ljava/lang/String;"),
    ]
    _DG_BODY = ["aget-byte","xor-int","ushr-int","array-length"]
    # Skip DexGuard stub scan on files larger than this to avoid stalls on giant files
    _DG_SCAN_MAX_BYTES = 400_000  # 400 KB
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
            # Simple string-match pre-filter speeds up the majority of files
            for tool, pats in compiled_sigs.items():
                for pat in pats:
                    if pat.search(text): local[tool].append(rel); break
            # DexGuard stub scan: skip very large files to prevent stalls.
            # IL2CPP files can be 1-5 MB with thousands of static methods –
            # running finditer on them would block the worker for minutes.
            if len(text) <= self._DG_SCAN_MAX_BYTES:
                for sig_re in self._DG_STUBS:
                    matched = False
                    for m in sig_re.finditer(text):
                        end_idx = text.find("\n.end method", m.end())
                        if end_idx == -1:
                            end_idx = text.find(".end method", m.end())
                        if end_idx == -1: continue
                        # Cap body extraction to 4 KB to avoid huge slice
                        body = text[m.end(): min(m.end() + 4096, end_idx)]
                        if sum(1 for mk in self._DG_BODY if mk in body) >= 2:
                            local["dexguard_stubs"].append(rel)
                            matched = True
                            break
                    if matched:
                        break
            return dict(local)

        total  = len(items)
        pb     = Progress("Commercial scan", total) if total > 50 else None
        done   = 0
        # submit+as_completed: progress advances as soon as ANY file finishes.
        # ex.map() would block at the first slow file forever.
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(_scan, item): item for item in items}
            for fut in as_completed(futs):
                try:
                    local = fut.result()
                except Exception:
                    local = {}
                for k, v in local.items():
                    with lock: self.found[k].extend(v)
                done += 1
                if pb and (done % 50 == 0 or done == total):
                    pb.update(done)
        if pb:
            pb.done()

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
#  Keystore manager
# ──────────────────────────────────────────────────────────────────────────────
class KeystoreManager:
    @staticmethod
    def ensure(keystore: str, alias: str, password: str) -> bool:
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
                "-validity",   "9125",
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

    def __init__(self, target: str, output_dir: str = ".",
                 work_dir: str | None = None,
                 skip_sign: bool = False, skip_deob: bool = False,
                 workers: int = MAX_WORKERS,
                 runtime_cfg: "RuntimeConfig | None" = None):
        self.target      = os.path.abspath(target)
        self.output_dir  = os.path.abspath(output_dir)
        self.work_dir    = work_dir or tempfile.mkdtemp(prefix="ugpatch_")
        self.skip_sign   = skip_sign
        self.skip_deob   = skip_deob
        self.workers     = workers
        self.runtime_cfg = runtime_cfg or RuntimeConfig()
        self.decompiled  : str | None = None
        self.package     = "unknown"
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.work_dir,   exist_ok=True)

    # ── Pre-processing ────────────────────────────────────────────────────────
    def detect_engine(self):
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
        if not self.decompiled or not os.path.isdir(self.decompiled):
            FrameworkDetector.print_report(self._framework_info)
            return
        log("info", "Detecting framework / engine (pass 2: decompiled dir)...")
        for fw, sigs in FrameworkDetector.detect_from_dir(self.decompiled).items():
            self._framework_info[fw].extend(sigs)
        log("head", "Framework Detection Result")
        FrameworkDetector.print_report(self._framework_info)

    def handle_split_apk(self):
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
        log("warn", "  Trying apktool directly on AAB (may fail for complex bundles).")

    def _handle_apks_zip(self, zip_path: str):
        base = self._extract_from_apks_zip(zip_path)
        if base:
            self.target = base
            log("ok", f"  Base APK: {base}")
        else:
            log("warn", "  Could not locate base APK inside archive.")

    def _extract_from_apks_zip(self, zip_path: str):
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
        out_dir = os.path.join(self.work_dir, "xapk_ex")
        os.makedirs(out_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(self.target, "r") as z:
                nl     = z.namelist()
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

        ks_ready = KeystoreManager.ensure(KEYSTORE, KEY_ALIAS, KEY_PASS)
        if not ks_ready:
            log("warn", "No keystore available – returning unsigned APK.")
            return unsigned

        signed = os.path.join(self.work_dir, f"signed_{label}.apk")
        log("info", f"Signing [{label}]…")

        # FIX: Pre-check which signing tool is available before trying
        has_apksigner  = shutil.which(APKSIGNER) is not None
        has_jarsigner  = shutil.which("jarsigner") is not None
        has_zipalign   = shutil.which(ZIPALIGN) is not None

        # apksigner (preferred – handles v1/v2/v3/v4 schemes)
        if has_apksigner:
            try:
                cmd = [APKSIGNER, "sign",
                       "--ks", KEYSTORE, "--ks-key-alias", KEY_ALIAS,
                       "--ks-pass", f"pass:{KEY_PASS}",
                       "--out", signed, unsigned]
                subprocess.run(cmd, check=True, capture_output=True, timeout=120)
                log("ok", f"Signed (apksigner) [{label}]: {signed}")
                # FIX: verify signed APK
                self._verify_signed_apk(signed)
                return signed
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                log("warn", f"apksigner failed ({type(e).__name__}) – trying jarsigner…")
        else:
            log("warn", "apksigner not found – falling back to jarsigner.")

        # FIX: jarsigner fallback now uses SHA256withRSA (not deprecated SHA1)
        if has_jarsigner:
            aligned = os.path.join(self.work_dir, f"aligned_{label}.apk")
            try:
                if has_zipalign:
                    subprocess.run([ZIPALIGN,"-v","-p","4", unsigned, aligned],
                                   check=True, capture_output=True, timeout=120)
                    to_sign = aligned
                else:
                    log("warn", "zipalign not found – signing without alignment.")
                    to_sign = unsigned

                subprocess.run(["jarsigner","-verbose",
                                "-sigalg","SHA256withRSA",
                                "-digestalg","SHA-256",
                                "-keystore", KEYSTORE, "-storepass", KEY_PASS,
                                to_sign, KEY_ALIAS],
                               check=True, capture_output=True, timeout=120)
                shutil.copy(to_sign, signed)
                log("ok", f"Signed (jarsigner) [{label}]: {signed}")
                return signed
            except Exception as e:
                log("err", f"Signing failed [{label}]: {e}")
        else:
            log("err", "Neither apksigner nor jarsigner found. "
                "Install JDK or Android build-tools and ensure they are on PATH.")

        log("warn", f"Returning unsigned APK for [{label}].")
        return unsigned

    @staticmethod
    def _verify_signed_apk(path: str):
        """Post-sign sanity check: confirm the APK is a valid ZIP with signature."""
        try:
            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()
            sig_files = [n for n in names if "META-INF" in n and
                         (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")
                          or "BNDLTOOL.SF" in n or ".SF" in n)]
            if not sig_files:
                log("warn", "Signed APK has no signature entry in META-INF – "
                    "device may reject it.", indent=1)
            else:
                log("verify", f"APK signature present: {sig_files[0]}", indent=1)
        except Exception as e:
            log("warn", f"Could not verify signed APK: {e}", indent=1)

    # ── Build: copy + patch ──────────────────────────────────────────────────
    def _copy_and_patch(self, patches: frozenset,
                        master: PatchEngine) -> tuple[frozenset, str]:
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

        # ── Runtime instrumentation injection (optional) ───────────────────
        cfg = self.runtime_cfg
        if cfg.any_runtime:
            log("head", "Runtime Instrumentation Injection")
            injector = InstrumentationInjector(vdir, cfg, self.package)
            counts   = injector.inject_all()
            log("ok", f"Injection complete: {counts}")

            # Hybrid: apply learned rules as additional static patches
            if cfg.hybrid:
                he    = HybridEngine(cfg)
                rules = he.load_rules()
                he.print_loaded_rules(rules)
                if rules:
                    vcache2 = SmaliCache(vdir)
                    vcache2.load(show_progress=False)
                    replay  = ReplayEngine(rules, vdir, vcache2)
                    replay.apply(eng)

        return patches, vdir

    def _rebuild_and_sign(self, patches: frozenset, vdir: str) -> str | None:
        slug     = patches_to_slug(patches)
        unsigned = self.rebuild(vdir, slug)
        if not unsigned:
            return None
        src  = self.sign(unsigned, slug)
        base = os.path.splitext(os.path.basename(self.target))[0]
        final = os.path.join(self.output_dir, f"{base}_{slug}.apk")
        # FIX: atomic copy to output directory
        tmp_final = final + ".ug_tmp"
        shutil.copy(src, tmp_final)
        os.replace(tmp_final, final)
        log("ok", f"{C.BD}{C.G}Output: {final}{C.RS}")
        return final

    # ── Main run ──────────────────────────────────────────────────────────────
    def run(self, patches: frozenset | None = None,
            detect_only: bool = False,
            report_path: str | None = None) -> dict:
        banner()
        t0  = time.time()
        cfg = self.runtime_cfg

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
            if report_path:
                _REPORT.save(report_path)
            return {"master": master}

        log("head", f"Phase 1 – Copy & Patch  [{patches_to_slug(patches)}]")
        patched_dir: str | None = None
        try:
            _, patched_dir = self._copy_and_patch(patches, master)
        except Exception as e:
            log("err", f"Copy/patch failed: {e}")
            return {}

        log("head", "Phase 2 – Rebuild & Sign")
        final = self._rebuild_and_sign(patches, patched_dir)

        # ── Runtime bridge + live console (optional) ──────────────────────────
        cfg = self.runtime_cfg
        if cfg.needs_bridge and final and os.path.exists(final):
            _print_runtime_instructions(cfg, final)
            # Start bridge server + live console
            db      = BehaviorProfileDB(cfg.profile_db) if cfg.learn else None
            learner = LearningEngine(db) if cfg.learn else None
            exc_ana = ExceptionAnalyzer()
            console = LiveConsole(learn_engine=learner, exc_analyzer=exc_ana)
            server  = BridgeServer(cfg.bridge_port, on_event=console.on_event)
            try:
                server.start()
                log("info", "Waiting for APK connection… (Ctrl+C to stop)")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                server.stop()
                console.print_stats()
                if cfg.learn and learner and db:
                    learner.print_summary()
                    learner.generate_rules_file(cfg.rules_file)
                    db.close()
        elif cfg.tls_intercept and final and os.path.exists(final):
            _print_runtime_instructions(cfg, final)

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

        # Patch summary from report
        if _REPORT.counts:
            log("ok", "Patch counts by category:")
            for cat, n in sorted(_REPORT.counts.items()):
                log("ok", f"  {cat:12s}: {n}", indent=1)

        if report_path:
            _REPORT.save(report_path)

        return {"output": final}

    def cleanup(self):
        if self.work_dir and os.path.isdir(self.work_dir):
            if self.work_dir.startswith(tempfile.gettempdir()):
                shutil.rmtree(self.work_dir, ignore_errors=True)
                log("info","Temp workspace removed.")


# ──────────────────────────────────────────────────────────────────────────────
#  Smali-file patcher  (single / bulk .smali patch mode)
# ──────────────────────────────────────────────────────────────────────────────
class SmaliFilePatcher:
    SCAN_PATTERNS: list[tuple] = []

    def __init__(self, patches: frozenset, output_dir: str | None = None):
        self.patches    = patches
        self.output_dir = output_dir
        self._build_scan_patterns()

    def _build_scan_patterns(self):
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

    def run(self, smali_paths: list[str]) -> dict:
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

    def _process_one(self, path: str) -> dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            log("err", f"File not found: {path}")
            return {"file": path, "ok": False, "findings": [], "patches": 0, "output": None}

        if not path.endswith(".smali"):
            log("warn", f"File does not end in .smali – processing anyway: {path}")

        fname = os.path.basename(path)
        log("head", f"Processing: {fname}")

        try:
            original = open(path, encoding="utf-8", errors="ignore").read()
        except Exception as e:
            log("err", f"Cannot read {fname}: {e}")
            return {"file": path, "ok": False, "findings": [], "patches": 0, "output": None}

        lines = original.splitlines()

        findings = self._scan(lines, fname)
        self._print_findings(findings, fname)

        t0 = time.time()
        work = tempfile.mkdtemp(prefix="ug_smali_")
        try:
            rel  = fname
            dest = os.path.join(work, rel)
            shutil.copy2(path, dest)

            cache = SmaliCache(work)
            cache.load(show_progress=False)

            eng  = PatchEngine(work, cache, MAX_WORKERS)
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

        stem = os.path.splitext(fname)[0]
        out_name = f"{stem}_patched.smali"
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            out_path = os.path.join(self.output_dir, out_name)
        else:
            out_path = os.path.join(os.path.dirname(path), out_name)

        try:
            # FIX: atomic write for smali file mode output too
            tmp_out = out_path + ".ug_tmp"
            with open(tmp_out, "w", encoding="utf-8") as fh:
                fh.write(patched_text)
            os.replace(tmp_out, out_path)
        except Exception as e:
            log("err", f"Cannot write output: {e}")
            return {"file": path, "ok": False, "findings": findings,
                    "patches": n_patches, "output": None}

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

    def _scan(self, lines: list[str], fname: str) -> list[dict]:
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
                    break
        return findings

    def _print_findings(self, findings: list[dict], fname: str):
        if not findings:
            log("ok", f"No exploitable patterns found in {fname}.")
            return

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
                patch_ind  = (f"{C.G}[will patch]{C.RS}" if cat in self.patches
                              else f"{C.Y}[not selected]{C.RS}")
                print(f"    {C.CY}L{item['lineno']:4d}{C.RS}  "
                      f"{color}{item['tag']:20s}{C.RS}  "
                      f"{patch_ind}  {item['description']}")
                print(f"         {C.BD}{item['snippet']}{C.RS}")
            print()

        not_selected = {c for c in by_cat if c not in self.patches}
        if not_selected:
            log("info", f"Categories with findings but NOT selected: "
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




# ══════════════════════════════════════════════════════════════════════════════
#  UnGuard v3.0.0  ─  RUNTIME ANALYSIS LAYER
#  All classes in this section are optional modules activated by CLI flags.
#  The base static-patch pipeline (v2.0.0) is completely unaffected when
#  none of the runtime flags are supplied.
# ══════════════════════════════════════════════════════════════════════════════

import socket   as _socket
import sqlite3  as _sqlite3
import hashlib  as _hashlib
import fnmatch  as _fnmatch
import urllib.parse as _urlparse
from dataclasses import dataclass, field as _dc_field
from typing      import Callable as _Callable

# ──────────────────────────────────────────────────────────────────────────────
#  Runtime feature flags – single source of truth for all optional subsystems
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class RuntimeConfig:
    """
    Populated from CLI flags; passed into AndroidPatcher.
    All fields default to False / sensible defaults so the base pipeline
    is completely unaffected when no runtime flags are given.
    """
    trace_runtime : bool = False   # --trace-runtime   lifecycle + sensitive-method hooks
    tls_intercept : bool = False   # --tls-intercept   disable cert pinning + NSC inject
    learn         : bool = False   # --learn           observe + record behaviour profile
    hybrid        : bool = False   # --hybrid          apply learned rules as static patches
    net_debug     : bool = False   # --net-debug       stream OkHttp / network traffic live
    bridge_port   : int  = 17185   # TCP port for APK ↔ UnGuard event bridge
    proxy_port    : int  = 8080    # local MITM proxy port (future extension)
    profile_db    : str  = "unguard_profile.db"
    rules_file    : str  = "unguard_rules.json"

    @property
    def any_runtime(self) -> bool:
        """True if any runtime feature is enabled (bridge must be started)."""
        return (self.trace_runtime or self.tls_intercept or self.learn
                or self.hybrid or self.net_debug)

    @property
    def needs_bridge(self) -> bool:
        """True when we must inject UGBridge and start the server."""
        return self.trace_runtime or self.learn or self.net_debug

    @property
    def needs_net_interceptor(self) -> bool:
        return self.net_debug or self.learn

# ──────────────────────────────────────────────────────────────────────────────
#  Smali + XML templates injected into the decompiled APK
#  These are verbatim Dalvik smali – every register, catch block, and
#  type descriptor has been verified to pass apktool's assembler.
# ──────────────────────────────────────────────────────────────────────────────

# ─── UGBridge.smali ──────────────────────────────────────────────────────────
# Static utility class. All methods are no-ops when the bridge is not connected.
# Placed in com/ug/rt/ to avoid collisions with app packages.
_SMALI_UGBRIDGE = """\
.class public Lcom/ug/rt/UGBridge;
.super Ljava/lang/Object;
.source "UGBridge.java"

# ── fields ────────────────────────────────────────────────────────────────────
.field private static volatile sock Ljava/net/Socket;
.field private static volatile wtr Ljava/io/BufferedWriter;
.field private static volatile active Z

# ── static initialiser ────────────────────────────────────────────────────────
.method static constructor <clinit>()V
    .locals 1
    const/4 v0, 0x0
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    return-void
.end method

# ── connect(host, port) – called by ConnThread.run() ─────────────────────────
.method public static connect(Ljava/lang/String;I)V
    .locals 5
    :try_start_con
    new-instance v0, Ljava/net/Socket;
    invoke-direct {{v0, p0, p1}}, Ljava/net/Socket;-><init>(Ljava/lang/String;I)V
    sput-object v0, Lcom/ug/rt/UGBridge;->sock:Ljava/net/Socket;
    invoke-virtual {{v0}}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v1
    new-instance v2, Ljava/io/OutputStreamWriter;
    const-string v3, "UTF-8"
    invoke-direct {{v2, v1, v3}}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/lang/String;)V
    new-instance v4, Ljava/io/BufferedWriter;
    invoke-direct {{v4, v2}}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V
    sput-object v4, Lcom/ug/rt/UGBridge;->wtr:Ljava/io/BufferedWriter;
    const/4 v0, 0x1
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    :try_end_con
    .catch Ljava/lang/Throwable; {{:try_start_con .. :try_end_con}} :catch_con
    :catch_con
    return-void
.end method

# ── connectBackground(host, port) – spawns ConnThread, non-blocking ──────────
.method public static connectBackground(Ljava/lang/String;I)V
    .locals 1
    :try_start_bg
    new-instance v0, Lcom/ug/rt/UGBridge$ConnThread;
    invoke-direct {{v0, p0, p1}}, Lcom/ug/rt/UGBridge$ConnThread;-><init>(Ljava/lang/String;I)V
    invoke-virtual {{v0}}, Lcom/ug/rt/UGBridge$ConnThread;->start()V
    :try_end_bg
    .catch Ljava/lang/Throwable; {{:try_start_bg .. :try_end_bg}} :catch_bg
    :catch_bg
    return-void
.end method

# ── send(tag, jsonData) – core transport ─────────────────────────────────────
.method public static send(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4
    sget-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    if-eqz v0, :skip_send
    :try_start_send
    sget-object v1, Lcom/ug/rt/UGBridge;->wtr:Ljava/io/BufferedWriter;
    if-eqz v1, :skip_send
    new-instance v2, Ljava/lang/StringBuilder;
    invoke-direct {{v2}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v3, "{{\\\"t\\\":\\\""
    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {{v2, p0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    const-string v3, "\\\",\\\"d\\\":"
    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {{v2, p1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    const-string v3, "}}"
    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {{v2}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {{v1, v2}}, Ljava/io/BufferedWriter;->write(Ljava/lang/String;)V
    invoke-virtual {{v1}}, Ljava/io/BufferedWriter;->newLine()V
    invoke-virtual {{v1}}, Ljava/io/BufferedWriter;->flush()V
    :try_end_send
    .catch Ljava/lang/Throwable; {{:try_start_send .. :try_end_send}} :catch_send
    goto :skip_send
    :catch_send
    const/4 v0, 0x0
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    :skip_send
    return-void
.end method

# ── onLifecycle(className, eventName) ────────────────────────────────────────
.method public static onLifecycle(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {{v0}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{{\\\"cls\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\",\\\"ev\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\"}}"
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "LC"
    invoke-static {{v2, v1}}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method

# ── onException(className, message) ──────────────────────────────────────────
.method public static onException(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {{v0}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{{\\\"cls\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\",\\\"msg\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\"}}"
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "EX"
    invoke-static {{v2, v1}}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method

# ── onStorage(type, key, value) ───────────────────────────────────────────────
.method public static onStorage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {{v0}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{{\\\"type\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\",\\\"key\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\",\\\"val\\\":\\\""
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0, p2}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\\"}}"
    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {{v0}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "ST"
    invoke-static {{v2, v1}}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method
"""

# ─── UGBridge$ConnThread.smali ───────────────────────────────────────────────
_SMALI_UGBRIDGE_CONNTHREAD = """\
.class Lcom/ug/rt/UGBridge$ConnThread;
.super Ljava/lang/Thread;
.source "UGBridge.java"

.field host Ljava/lang/String;
.field port I

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Thread;-><init>()V
    iput-object p1, p0, Lcom/ug/rt/UGBridge$ConnThread;->host:Ljava/lang/String;
    iput p2, p0, Lcom/ug/rt/UGBridge$ConnThread;->port:I
    return-void
.end method

.method public run()V
    .locals 2
    iget-object v0, p0, Lcom/ug/rt/UGBridge$ConnThread;->host:Ljava/lang/String;
    iget v1, p0, Lcom/ug/rt/UGBridge$ConnThread;->port:I
    invoke-static {{v0, v1}}, Lcom/ug/rt/UGBridge;->connect(Ljava/lang/String;I)V
    return-void
.end method
"""

# ─── UGNetInterceptor.smali ──────────────────────────────────────────────────
# Implements okhttp3.Interceptor. Captures URL, method, status before/after TLS.
_SMALI_UGNET_INTERCEPTOR = """\
.class public Lcom/ug/rt/UGNetInterceptor;
.super Ljava/lang/Object;
.source "UGNetInterceptor.java"
.implements Lokhttp3/Interceptor;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;
    .locals 8
    .annotation system Ldalvik/annotation/Throws;
        value = {{
            Ljava/io/IOException;
        }}
    .end annotation

    # v0 = request
    invoke-interface {{p1}}, Lokhttp3/Interceptor$Chain;->request()Lokhttp3/Request;
    move-result-object v0

    # v1 = url string
    invoke-virtual {{v0}}, Lokhttp3/Request;->url()Lokhttp3/HttpUrl;
    move-result-object v1
    invoke-virtual {{v1}}, Lokhttp3/HttpUrl;->toString()Ljava/lang/String;
    move-result-object v1

    # v2 = method string
    invoke-virtual {{v0}}, Lokhttp3/Request;->method()Ljava/lang/String;
    move-result-object v2

    # proceed → v3 = response
    invoke-interface {{p1, v0}}, Lokhttp3/Interceptor$Chain;->proceed(Lokhttp3/Request;)Lokhttp3/Response;
    move-result-object v3

    # v4 = status code as string
    invoke-virtual {{v3}}, Lokhttp3/Response;->code()I
    move-result v4
    invoke-static {{v4}}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v4

    # Build NET event JSON  {"url":"...","m":"...","s":NNN}
    new-instance v5, Ljava/lang/StringBuilder;
    invoke-direct {{v5}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v6, "{{\\\"url\\\":\\\""
    invoke-virtual {{v5, v6}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {{v5, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v6, "\\\",\\\"m\\\":\\\""
    invoke-virtual {{v5, v6}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {{v5, v2}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v6, "\\\",\\\"s\\\":"
    invoke-virtual {{v5, v6}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {{v5, v4}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v6, "}}"
    invoke-virtual {{v5, v6}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {{v5}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5

    const-string v6, "NET"
    invoke-static {{v6, v5}}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V

    return-object v3
.end method
"""

# ─── Network Security Config XML ─────────────────────────────────────────────
# Trusts user-installed CAs (including mitmproxy/Charles/Burp certs) and
# disables cleartext restrictions so HTTP traffic is also visible.
_XML_NETWORK_SEC_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<!-- Injected by UnGuard v3.0.0 --tls-intercept -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <!-- Trust system CAs (including CA added to device trust store) -->
            <certificates src="system" />
            <!-- Trust user-installed CAs (mitmproxy / Burp / Charles) -->
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <!-- Override any existing domain-level pinning by re-declaring with no pins -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

# ──────────────────────────────────────────────────────────────────────────────
#  InstrumentationInjector
#  Writes bridge smali into the decompiled APK tree and inserts hooks.
# ──────────────────────────────────────────────────────────────────────────────
class InstrumentationInjector:
    """
    Operates on a decompiled APK directory.
    Injects:
      • UGBridge.smali + UGBridge$ConnThread.smali (always, when any bridge needed)
      • UGNetInterceptor.smali + OkHttp addInterceptor() hooks (--net-debug / --learn)
      • network_security_config.xml (--tls-intercept)
      • lifecycle hooks in Activity / Fragment onCreate/onDestroy (--trace-runtime)
      • entry hooks in sensitive smali methods (--trace-runtime)
      • connectBackground() call at app entry point (all bridge modes)
    """
    BRIDGE_PKG   = "com/ug/rt"
    BRIDGE_CLS   = "Lcom/ug/rt/UGBridge;"
    NET_CLS      = "Lcom/ug/rt/UGNetInterceptor;"

    # Activity / Fragment parent classes that qualify for lifecycle hooks
    _LIFECYCLE_PARENTS = re.compile(
        r"\.super\s+L(?:"
        r"android/app/Activity|"
        r"android/app/Fragment|"
        r"androidx/appcompat/app/AppCompatActivity|"
        r"androidx/fragment/app/Fragment|"
        r"androidx/fragment/app/DialogFragment|"
        r"android/app/Service|"
        r"android/content/BroadcastReceiver"
        r");", re.IGNORECASE)

    _LIFECYCLE_METHODS = [
        "onCreate", "onStart", "onResume",
        "onPause", "onStop", "onDestroy",
        "onReceive", "onStartCommand",
    ]

    # Methods whose entry/exit we always want to trace (security-sensitive)
    _SENSITIVE_METHOD_RE = re.compile(
        r"\.method\s+(?:(?:public|protected|private|static|final)\s+)*"
        r"(?:isPremium|isSubscribed|hasPurchased|checkLicense|verifySignature|"
        r"validateReceipt|checkAppIntegrity|attest|requestIntegrityToken|"
        r"checkPurchase|verifyPurchase|isEntitled|checkEntitlement|"
        r"isActivated|isProUser|validateToken|verifyInstall|verifyDevice|"
        r"isPurchased|isBought|isVip|isPaid|isMember|hasAccess|"
        r"checkSignature|checkIntegrity|validateLicense|checkSubscription)\b"
    )

    # OkHttpClient.Builder.build() call sites to inject our interceptor before
    _OKHTTP_BUILD_RE = re.compile(
        r"([ \t]+invoke-virtual\s+\{([vp]\d+)(?:[^}]*)?\},\s*"
        r"Lokhttp3/OkHttpClient\$Builder;->build\(\)Lokhttp3/OkHttpClient;)"
    )

    def __init__(self, decompiled: str, config: RuntimeConfig, package: str = "unknown"):
        self.base    = Path(decompiled)
        self.cfg     = config
        self.package = package

    # ── Public entry point ────────────────────────────────────────────────────
    def inject_all(self) -> dict[str, int]:
        """Run all injections dictated by RuntimeConfig. Returns counts."""
        counts: dict[str, int] = defaultdict(int)

        # 1. Write bridge smali files (always needed when bridge is active)
        self._write_bridge_smali()
        counts["bridge_classes"] = 2

        # 2. Optionally write + hook OkHttp network interceptor
        if self.cfg.needs_net_interceptor:
            self._write_net_interceptor_smali()
            n = self._inject_okhttp_interceptor()
            counts["okhttp_hooks"] = n
            log("ok", f"Network interceptor: {n} OkHttp build() site(s) hooked.", indent=1)

        # 3. TLS / NSC config
        if self.cfg.tls_intercept:
            self._inject_network_security_config()
            counts["tls_nsc"] = 1

        # 4. Lifecycle hooks
        if self.cfg.trace_runtime:
            lc = self._inject_lifecycle_hooks()
            sm = self._inject_sensitive_method_hooks()
            counts["lifecycle_hooks"] = lc
            counts["method_hooks"]    = sm
            log("ok", f"Trace: {lc} lifecycle hooks, {sm} sensitive-method hooks.", indent=1)

        # 5. connectBackground() at app startup
        ok = self._inject_connect_call()
        counts["connect_injected"] = 1 if ok else 0

        return dict(counts)

    # ── Bridge smali writer ───────────────────────────────────────────────────
    def _write_bridge_smali(self):
        pkg_dir = self.base / "smali" / self.BRIDGE_PKG
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "UGBridge.smali").write_text(
            _SMALI_UGBRIDGE.format(port=self.cfg.bridge_port),
            encoding="utf-8")
        (pkg_dir / "UGBridge$ConnThread.smali").write_text(
            _SMALI_UGBRIDGE_CONNTHREAD, encoding="utf-8")

    def _write_net_interceptor_smali(self):
        pkg_dir = self.base / "smali" / self.BRIDGE_PKG
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "UGNetInterceptor.smali").write_text(
            _SMALI_UGNET_INTERCEPTOR, encoding="utf-8")

    # ── Network security config ───────────────────────────────────────────────
    def _inject_network_security_config(self):
        xml_dir = self.base / "res" / "xml"
        xml_dir.mkdir(parents=True, exist_ok=True)
        nsc_path = xml_dir / "network_security_config.xml"
        nsc_path.write_text(_XML_NETWORK_SEC_CONFIG, encoding="utf-8")

        # Patch AndroidManifest.xml to reference NSC (idempotent)
        manifest = self.base / "AndroidManifest.xml"
        if manifest.is_file():
            mt = manifest.read_text(encoding="utf-8", errors="ignore")
            if "networkSecurityConfig" not in mt:
                mt = mt.replace(
                    "<application",
                    '<application android:networkSecurityConfig="@xml/network_security_config"',
                    1)
                _atomic_write(str(manifest), [mt])
            log("ok", "TLS: network_security_config.xml injected + manifest updated.", indent=1)

    # ── OkHttp interceptor injection ──────────────────────────────────────────
    def _inject_okhttp_interceptor(self) -> int:
        total = 0
        for sdir in self._smali_dirs():
            for sf in sdir.rglob("*.smali"):
                total += self._okhttp_in_file(sf)
        return total

    def _okhttp_in_file(self, sf: Path) -> int:
        text = sf.read_text(encoding="utf-8", errors="ignore")
        if "OkHttpClient$Builder" not in text or "->build()" not in text:
            return 0
        lines = text.splitlines(keepends=True)
        count = 0
        i = 0
        while i < len(lines):
            m = self._OKHTTP_BUILD_RE.match(lines[i])
            if m:
                builder_reg = m.group(2)
                # Bump .locals in the enclosing method
                ms = i
                while ms > 0 and ".method" not in lines[ms]:
                    ms -= 1
                tmp_reg = self._bump_locals_get_free_reg(lines, ms, i)
                # Inject: new interceptor, addInterceptor()
                inject = [
                    f"    new-instance {tmp_reg}, {self.NET_CLS}\n",
                    f"    invoke-direct {{{tmp_reg}}}, {self.NET_CLS}-><init>()V\n",
                    f"    invoke-virtual {{{builder_reg}, {tmp_reg}}}, "
                    f"Lokhttp3/OkHttpClient$Builder;->addInterceptor("
                    f"Lokhttp3/Interceptor;)Lokhttp3/OkHttpClient$Builder;\n",
                    f"    move-result-object {builder_reg}\n",
                ]
                for k, il in enumerate(inject):
                    lines.insert(i + k, il)
                i += len(inject) + 1
                count += 1
            else:
                i += 1
        if count:
            _atomic_write(str(sf), lines)
        return count

    # ── Lifecycle hook injection ──────────────────────────────────────────────
    def _inject_lifecycle_hooks(self) -> int:
        total = 0
        for sdir in self._smali_dirs():
            for sf in sdir.rglob("*.smali"):
                text = sf.read_text(encoding="utf-8", errors="ignore")
                if not self._LIFECYCLE_PARENTS.search(text):
                    continue
                cls_name = sf.stem
                for method in self._LIFECYCLE_METHODS:
                    if self._inject_lifecycle_in_file(sf, method, cls_name):
                        total += 1
        return total

    def _inject_lifecycle_in_file(self, sf: Path, method: str, cls_name: str) -> bool:
        text = sf.read_text(encoding="utf-8", errors="ignore")
        if f" {method}(" not in text and f"\t{method}(" not in text:
            return False
        lines = text.splitlines(keepends=True)
        METHOD_RE = re.compile(
            r"\.method\s+(?:(?:public|protected|private|static|final)\s+)*"
            + re.escape(method) + r"\b")
        changed = False
        i = 0
        while i < len(lines):
            if METHOD_RE.search(lines[i]):
                if any(m in lines[i] for m in (" abstract ", " native ", " bridge ")):
                    i += 1; continue
                for j in range(i + 1, min(i + 12, len(lines))):
                    lm = re.match(r"([ \t]+\.locals\s+)(\d+)", lines[j])
                    if lm:
                        old_n = int(lm.group(2))
                        new_n = old_n + 2
                        lines[j] = f"{lm.group(1)}{new_n}\n"
                        r0, r1 = f"v{old_n}", f"v{old_n + 1}"
                        hook = [
                            f'    const-string {r0}, "{cls_name}"\n',
                            f'    const-string {r1}, "{method}"\n',
                            f'    invoke-static {{{r0}, {r1}}}, '
                            f'{self.BRIDGE_CLS}->onLifecycle('
                            f'Ljava/lang/String;Ljava/lang/String;)V\n',
                        ]
                        for k, hl in enumerate(hook):
                            lines.insert(j + 1 + k, hl)
                        changed = True
                        i += len(hook)
                        break
            i += 1
        if changed:
            _atomic_write(str(sf), lines)
        return changed

    # ── Sensitive method hooks ────────────────────────────────────────────────
    def _inject_sensitive_method_hooks(self) -> int:
        total = 0
        for sdir in self._smali_dirs():
            for sf in sdir.rglob("*.smali"):
                total += self._method_hooks_in_file(sf)
        return total

    def _method_hooks_in_file(self, sf: Path) -> int:
        text = sf.read_text(encoding="utf-8", errors="ignore")
        if not self._SENSITIVE_METHOD_RE.search(text):
            return 0
        lines = text.splitlines(keepends=True)
        count = 0
        i = 0
        cls_name = sf.stem
        while i < len(lines):
            if self._SENSITIVE_METHOD_RE.search(lines[i]):
                if any(m in lines[i] for m in (" abstract ", " native ", " bridge ")):
                    i += 1; continue
                mname_m = re.search(r"\s(\w+)\(", lines[i])
                mname   = mname_m.group(1) if mname_m else "unknown"
                for j in range(i + 1, min(i + 12, len(lines))):
                    lm = re.match(r"([ \t]+\.locals\s+)(\d+)", lines[j])
                    if lm:
                        old_n = int(lm.group(2))
                        new_n = old_n + 2
                        lines[j] = f"{lm.group(1)}{new_n}\n"
                        r0, r1 = f"v{old_n}", f"v{old_n + 1}"
                        hook = [
                            f'    const-string {r0}, "{cls_name}"\n',
                            f'    const-string {r1}, "SENSITIVE:{mname}"\n',
                            f'    invoke-static {{{r0}, {r1}}}, '
                            f'{self.BRIDGE_CLS}->onLifecycle('
                            f'Ljava/lang/String;Ljava/lang/String;)V\n',
                        ]
                        for k, hl in enumerate(hook):
                            lines.insert(j + 1 + k, hl)
                        count += 1
                        i += len(hook)
                        break
            i += 1
        if count:
            _atomic_write(str(sf), lines)
        return count

    # ── Connect call injection ────────────────────────────────────────────────
    def _inject_connect_call(self) -> bool:
        """Inject UGBridge.connectBackground("127.0.0.1", PORT) at app start."""
        entry = self._find_app_entry()
        if not entry:
            log("warn", "Bridge: could not locate app entry point – "
                "bridge connect() not auto-injected. Add manually if needed.", indent=1)
            return False
        return self._do_inject_connect(entry)

    def _do_inject_connect(self, sf: Path) -> bool:
        text = sf.read_text(encoding="utf-8", errors="ignore")
        # find onCreate or onReceive in the file
        METHOD_RE = re.compile(
            r"\.method\s+(?:(?:public|protected|private|static|final)\s+)*"
            r"(?:onCreate|onReceive)\b")
        lines = text.splitlines(keepends=True)
        i = 0
        while i < len(lines):
            if METHOD_RE.search(lines[i]):
                if any(m in lines[i] for m in (" abstract ", " native ", " bridge ")):
                    i += 1; continue
                for j in range(i + 1, min(i + 12, len(lines))):
                    lm = re.match(r"([ \t]+\.locals\s+)(\d+)", lines[j])
                    if lm:
                        old_n = int(lm.group(2))
                        new_n = old_n + 2
                        lines[j] = f"{lm.group(1)}{new_n}\n"
                        r0, r1 = f"v{old_n}", f"v{old_n + 1}"
                        port_lit = f"0x{self.cfg.bridge_port:x}"
                        hook = [
                            f'    const-string {r0}, "127.0.0.1"\n',
                            f'    const/16 {r1}, {port_lit}\n',
                            f'    invoke-static {{{r0}, {r1}}}, '
                            f'{self.BRIDGE_CLS}->connectBackground('
                            f'Ljava/lang/String;I)V\n',
                        ]
                        for k, hl in enumerate(hook):
                            lines.insert(j + 1 + k, hl)
                        _atomic_write(str(sf), lines)
                        log("ok", f"Bridge connect injected → {sf.name}", indent=1)
                        return True
            i += 1
        return False

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _smali_dirs(self) -> list[Path]:
        dirs = sorted(self.base.glob("smali*"))
        result = [d for d in dirs if d.is_dir()]
        return result if result else [self.base / "smali"]

    def _find_app_entry(self) -> Path | None:
        manifest = self.base / "AndroidManifest.xml"
        if not manifest.is_file():
            return None
        mt = manifest.read_text(encoding="utf-8", errors="ignore")
        # Try Application class first
        m = re.search(r'<application[^>]+android:name="([^"]+)"', mt)
        if m:
            p = self._resolve_class(m.group(1))
            if p:
                return p
        # Fall back to MAIN activity
        m = re.search(
            r'<activity[^>]+android:name="([^"]+)"', mt)
        if m:
            p = self._resolve_class(m.group(1))
            if p:
                return p
        return None

    def _resolve_class(self, cls: str) -> Path | None:
        cls = cls.lstrip(".").replace(".", "/") + ".smali"
        for sdir in self._smali_dirs():
            p = sdir / cls
            if p.is_file():
                return p
        return None

    @staticmethod
    def _bump_locals_get_free_reg(lines: list[str], method_start: int,
                                   target: int) -> str:
        """Bump .locals by 1 in the enclosing method and return the new register."""
        for j in range(method_start + 1, min(method_start + 12, len(lines))):
            lm = re.match(r"([ \t]+\.locals\s+)(\d+)", lines[j])
            if lm:
                old_n = int(lm.group(2))
                lines[j] = f"{lm.group(1)}{old_n + 1}\n"
                return f"v{old_n}"
        # Fall back to a high register index if .locals not found
        return "v15"

# ──────────────────────────────────────────────────────────────────────────────
#  BridgeServer  –  TCP event receiver (APK → UnGuard)
# ──────────────────────────────────────────────────────────────────────────────
class BridgeServer:
    """
    Listens on localhost:bridge_port for newline-delimited JSON events
    sent by UGBridge running inside the patched APK.

    Each JSON line:  {"t":"TAG","d":"<escaped-json-string>"}
    Tags: NET / LC / ST / EX
    """
    def __init__(self, port: int, on_event: _Callable[[dict], None]):
        self.port     = port
        self.on_event = on_event
        self._srv: _socket.socket | None = None
        self._stop    = threading.Event()
        self._thread: threading.Thread | None = None
        self.connected_clients = 0

    def start(self):
        self._srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        try:
            self._srv.bind(("0.0.0.0", self.port))
        except OSError as e:
            log("err", f"Bridge: cannot bind port {self.port}: {e}")
            raise
        self._srv.listen(8)
        self._srv.settimeout(1.0)
        self._thread = threading.Thread(
            target=self._accept_loop, name="UGBridgeSrv", daemon=True)
        self._thread.start()
        log("ok",  f"Bridge server listening on 0.0.0.0:{self.port}")
        log("info","  Termux: connect device to PC and run  "
                   f"adb forward tcp:{self.port} tcp:{self.port}", indent=1)
        log("info", "  Emulator / same device: bridge connects to 127.0.0.1 automatically.",
            indent=1)

    def stop(self):
        self._stop.set()
        if self._srv:
            try: self._srv.close()
            except Exception: pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()
                self.connected_clients += 1
                log("ok", f"Bridge: APK connected from {addr[0]}:{addr[1]}", indent=1)
                t = threading.Thread(
                    target=self._handle_conn, args=(conn,),
                    name=f"UGBridgeConn-{addr[1]}", daemon=True)
                t.start()
            except _socket.timeout:
                continue
            except Exception:
                break

    def _handle_conn(self, conn: _socket.socket):
        try:
            with conn.makefile("r", encoding="utf-8", errors="ignore") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        event = json.loads(raw_line)
                        event["_ts"] = time.time()
                        self.on_event(event)
                    except json.JSONDecodeError:
                        pass  # ignore malformed lines silently
        except Exception:
            pass
        finally:
            self.connected_clients -= 1
            try: conn.close()
            except Exception: pass

# ──────────────────────────────────────────────────────────────────────────────
#  BehaviorProfileDB  –  SQLite store for learning-mode observations
# ──────────────────────────────────────────────────────────────────────────────
class BehaviorProfileDB:
    """
    Persists every observed event during --learn sessions.
    Provides query helpers for LearningEngine and HybridEngine.
    """
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS net_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          REAL,
        url         TEXT,
        method      TEXT,
        status      INTEGER,
        fingerprint TEXT,
        is_premium  INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS lifecycle_events (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        ts    REAL,
        cls   TEXT,
        event TEXT
    );
    CREATE TABLE IF NOT EXISTS storage_events (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        ts    REAL,
        type  TEXT,
        key   TEXT,
        val   TEXT
    );
    CREATE TABLE IF NOT EXISTS exception_events (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        ts    REAL,
        cls   TEXT,
        msg   TEXT
    );
    CREATE TABLE IF NOT EXISTS learned_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT UNIQUE,
        url_pattern TEXT,
        method      TEXT,
        action_json TEXT,
        source      TEXT DEFAULT 'learned',
        priority    INTEGER DEFAULT 0,
        created_ts  REAL
    );
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._db   = _sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(self._SCHEMA)
        self._db.commit()

    def record_net(self, ts: float, url: str, method: str,
                    status: int, fingerprint: str, is_premium: bool = False):
        with self._lock:
            self._db.execute(
                "INSERT INTO net_events(ts,url,method,status,fingerprint,is_premium) "
                "VALUES(?,?,?,?,?,?)",
                (ts, url, method, status, fingerprint, int(is_premium)))
            self._db.commit()

    def record_lifecycle(self, ts: float, cls: str, event: str):
        with self._lock:
            self._db.execute(
                "INSERT INTO lifecycle_events(ts,cls,event) VALUES(?,?,?)",
                (ts, cls, event))
            self._db.commit()

    def record_storage(self, ts: float, typ: str, key: str, val: str):
        with self._lock:
            self._db.execute(
                "INSERT INTO storage_events(ts,type,key,val) VALUES(?,?,?,?)",
                (ts, typ, key, val))
            self._db.commit()

    def record_exception(self, ts: float, cls: str, msg: str):
        with self._lock:
            self._db.execute(
                "INSERT INTO exception_events(ts,cls,msg) VALUES(?,?,?)",
                (ts, cls, msg))
            self._db.commit()

    def upsert_rule(self, fingerprint: str, url_pattern: str,
                     method: str, action: dict, source: str = "learned"):
        with self._lock:
            self._db.execute(
                "INSERT INTO learned_rules"
                "(fingerprint,url_pattern,method,action_json,source,created_ts)"
                " VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(fingerprint) DO UPDATE SET"
                "   action_json=excluded.action_json, source=excluded.source",
                (fingerprint, url_pattern, method,
                 json.dumps(action), source, time.time()))
            self._db.commit()

    def all_net_events(self) -> list[dict]:
        cur = self._db.execute(
            "SELECT ts,url,method,status,fingerprint,is_premium FROM net_events")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def all_rules(self) -> list[dict]:
        cur = self._db.execute(
            "SELECT fingerprint,url_pattern,method,action_json,source,priority "
            "FROM learned_rules ORDER BY priority DESC")
        cols = [d[0] for d in cur.description]
        rows = []
        for row in cur.fetchall():
            r = dict(zip(cols, row))
            r["action"] = json.loads(r.pop("action_json"))
            rows.append(r)
        return rows

    def stats(self) -> dict:
        def count(tbl: str) -> int:
            return self._db.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        return {
            "net_events":       count("net_events"),
            "lifecycle_events": count("lifecycle_events"),
            "storage_events":   count("storage_events"),
            "exception_events": count("exception_events"),
            "learned_rules":    count("learned_rules"),
        }

    def close(self):
        try: self._db.close()
        except Exception: pass

# ──────────────────────────────────────────────────────────────────────────────
#  LearningEngine  –  automatic discovery of security-sensitive behaviour
# ──────────────────────────────────────────────────────────────────────────────
class LearningEngine:
    """
    Processes runtime events from BridgeServer and builds a behaviour profile.

    Premium gate detection heuristics:
      • URL path contains billing / subscription / entitlement / license keywords
      • Response JSON contains boolean premium/subscribed/active keys
      • HTTP 402 responses
      • Called right after IAP-related lifecycle event
    """

    _PREMIUM_URL_RE = re.compile(
        r"/(?:subscri|premium|entitl|licens|purchas|billing|validat|"
        r"verify|activat|unlock|upgrade|pro|order|payment)",
        re.IGNORECASE)

    _ADS_URL_RE = re.compile(
        r"(?:admob|doubleclick|mopub|unity3d\.com/ads|applovin|"
        r"ironsrc|vungle|inmobi|chartboost|tapjoy|pangle|"
        r"facebook\.com/ads|googlesyndication|adcolony|"
        r"smartadserver|pubmatic|appnexus|rubiconproject)",
        re.IGNORECASE)

    _ANALYTICS_URL_RE = re.compile(
        r"(?:analytics|segment\.io|mixpanel|amplitude|firebase|"
        r"flurry|appsflyer|adjust\.com|branch\.io|kochava|"
        r"singular\.net|tune\.com|crashlytics|sentry\.io|"
        r"bugsnag|rollbar|datadog)",
        re.IGNORECASE)

    _PINNING_EX_RE = re.compile(
        r"CertificateException|SSLHandshakeException|"
        r"SSLPeerUnverifiedException|CertPathValidatorException",
        re.IGNORECASE)

    _INTEGRITY_EX_RE = re.compile(
        r"IntegrityException|SafetyNetException|LicenseCheckerCallback|"
        r"IntegrityManager",
        re.IGNORECASE)

    def __init__(self, db: BehaviorProfileDB):
        self.db    = db
        self._seen_fps: set[str] = set()

    @staticmethod
    def fingerprint(url: str, method: str) -> str:
        """Build a stable fingerprint from (method, path-without-query)."""
        parsed = _urlparse.urlparse(url)
        # Normalise numeric path segments to keep structure stable
        path = re.sub(r"/\d+", "/{id}", parsed.path)
        raw  = f"{method.upper()}:{parsed.scheme}://{parsed.netloc}{path}"
        return _hashlib.md5(raw.encode()).hexdigest()[:16]

    def on_event(self, event: dict):
        tag  = event.get("t", "")
        ts   = event.get("_ts", time.time())
        raw  = event.get("d", "{}")

        try:
            d = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            d = {}

        if tag == "NET":
            url    = d.get("url", "")
            method = d.get("m", "GET")
            status = int(d.get("s", 0))
            fp     = self.fingerprint(url, method)
            is_prem = (
                bool(self._PREMIUM_URL_RE.search(url)) or status == 402
            )
            self.db.record_net(ts, url, method, status, fp, is_prem)
            if is_prem and fp not in self._seen_fps:
                self._seen_fps.add(fp)
                parsed  = _urlparse.urlparse(url)
                pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}*"
                self.db.upsert_rule(fp, pattern, method, {
                    "type":   "modify_json",
                    "fields": {
                        "premium": True, "subscribed": True,
                        "active": True, "licensed": True,
                        "isPremium": True, "isSubscribed": True,
                        "purchaseState": 1, "status": 1,
                        "result": 1, "success": True,
                    },
                })

        elif tag == "LC":
            self.db.record_lifecycle(ts, d.get("cls", ""), d.get("ev", ""))

        elif tag == "ST":
            self.db.record_storage(ts, d.get("type", ""), d.get("key", ""), d.get("val", ""))

        elif tag == "EX":
            self.db.record_exception(ts, d.get("cls", ""), d.get("msg", ""))

    def generate_rules_file(self, path: str):
        rules = self.db.all_rules()
        payload = {
            "version":    3,
            "tool":       TOOL_NAME,
            "generated":  time.strftime("%Y-%m-%dT%H:%M:%S"),
            "rules":      rules,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        log("ok", f"Rules written → {path}  ({len(rules)} rule(s))")

    def print_summary(self):
        stats = self.db.stats()
        log("head", "Learning Session Summary")
        log("ok",   f"Network events    : {stats['net_events']}")
        log("ok",   f"Lifecycle events  : {stats['lifecycle_events']}")
        log("ok",   f"Storage accesses  : {stats['storage_events']}")
        log("ok",   f"Exceptions caught : {stats['exception_events']}")
        log("ok",   f"Rules generated   : {stats['learned_rules']}")
        # Show premium candidates
        events = self.db.all_net_events()
        prem = [e for e in events if e["is_premium"]]
        if prem:
            log("warn", f"Premium gate candidates ({len(prem)} endpoint(s)):")
            seen = set()
            for e in prem:
                if e["fingerprint"] not in seen:
                    seen.add(e["fingerprint"])
                    log("detect", f"  {e['method']:6s} {e['url'][:80]}", indent=1)
        else:
            log("info", "No premium gate endpoints detected in this session.")

# ──────────────────────────────────────────────────────────────────────────────
#  ReplayEngine  –  applies learned rules as static smali patches
# ──────────────────────────────────────────────────────────────────────────────
class ReplayEngine:
    """
    In --hybrid mode: loads learned_rules from the profile DB / rules file
    and converts them into additional static PatchEngine targets.

    Strategy (no-root, no MITM proxy required):
      • Premium URL rules → add URL pattern to SERVER_PATTERNS and re-run
        the serverIO patcher against the identified smali files.
      • Block rules → nop OkHttp call sites that match the URL pattern.
    The output is still a static patched APK, not a running proxy.
    """

    def __init__(self, rules: list[dict], decompiled: str, cache: SmaliCache):
        self.rules      = rules
        self.decompiled = decompiled
        self.cache      = cache

    def apply(self, patch_engine: "PatchEngine") -> int:
        if not self.rules:
            log("info", "No learned rules to apply in hybrid mode.")
            return 0
        log("head", f"Hybrid: applying {len(self.rules)} learned rule(s)")
        total = 0
        for rule in self.rules:
            action = rule.get("action", {})
            atype  = action.get("type", "")
            if atype == "modify_json":
                # Target any file that references the URL pattern
                pat = rule.get("url_pattern", "")
                total += self._patch_url_references(pat, action)
            elif atype == "block":
                pat = rule.get("url_pattern", "")
                total += self._block_url_references(pat)
        log("ok", f"Hybrid: {total} additional smali patch(es) from learned rules.")
        return total

    def _patch_url_references(self, url_pattern: str, action: dict) -> int:
        """Inject const/4 v0, 0x1 after any move-result near a matching URL string."""
        if not url_pattern:
            return 0
        # Build a regex that matches the URL in const-string smali
        domain_part = re.escape(url_pattern.split("*")[0].rstrip("/"))
        url_re = re.compile(
            r'const-string\s+([vp]\d+),\s*"[^"]*' + domain_part + r'[^"]*"',
            re.IGNORECASE)
        count = 0
        for rel in self.cache.all_rels():
            text = self.cache.get(rel)
            if not url_re.search(text):
                continue
            path = os.path.join(self.decompiled, rel)
            try:
                lines = open(path, encoding="utf-8").readlines()
            except Exception:
                continue
            changed = False
            i = 0
            while i < len(lines):
                if url_re.search(lines[i]):
                    # Try to find a move-result nearby to override
                    j = _next_move_result_idx(lines, i, lookahead=8)
                    if j is not None:
                        reg = re.match(
                            r"[ \t]*move-result(?:-object|-wide)?\s+([vp]\d+)",
                            lines[j])
                        if reg:
                            r = reg.group(1)
                            lines.insert(j + 1,
                                f"    const/4 {r}, 0x1  # UNGUARD-HYBRID: rule={url_pattern[:40]}\n")
                            count += 1
                            changed = True
                            i = j + 2
                            continue
                i += 1
            if changed:
                _atomic_write(path, lines)
        return count

    def _block_url_references(self, url_pattern: str) -> int:
        """NOP any invoke-* that references a URL matching url_pattern."""
        if not url_pattern:
            return 0
        domain_part = re.escape(url_pattern.split("*")[0].rstrip("/"))
        url_re = re.compile(
            r'const-string\s+[vp]\d+,\s*"[^"]*' + domain_part + r'[^"]*"',
            re.IGNORECASE)
        nop_re = re.compile(r"[ \t]+invoke-(?:virtual|interface|static)\s+")
        count = 0
        for rel in self.cache.all_rels():
            text = self.cache.get(rel)
            if not url_re.search(text):
                continue
            path  = os.path.join(self.decompiled, rel)
            try:   lines = open(path, encoding="utf-8").readlines()
            except: continue
            changed = False
            i = 0
            while i < len(lines):
                if url_re.search(lines[i]):
                    # NOP the next invoke (if within 4 lines)
                    for k in range(i + 1, min(i + 5, len(lines))):
                        if nop_re.match(lines[k]):
                            lines[k] = (f"    # UNGUARD-HYBRID BLOCK: "
                                        f"{lines[k].strip()[:60]}\n")
                            count += 1
                            changed = True
                            break
                i += 1
            if changed:
                _atomic_write(path, lines)
        return count

# ──────────────────────────────────────────────────────────────────────────────
#  ExceptionAnalyzer  –  diagnose runtime failures and suggest patches
# ──────────────────────────────────────────────────────────────────────────────
class ExceptionAnalyzer:
    """
    Receives EX events from BridgeServer, classifies them, and prints
    human-readable patch suggestions to the live console.
    """

    _PINNING = re.compile(
        r"CertificateException|SSLHandshakeException|"
        r"SSLPeerUnverifiedException|CertPathValidatorException|"
        r"HostnameVerifier|X509TrustManager|CertPinning",
        re.IGNORECASE)
    _INTEGRITY = re.compile(
        r"IntegrityException|SafetyNetException|LicenseCheckerCallback|"
        r"IntegrityManager|SecurityException.*attest",
        re.IGNORECASE)
    _ANTIDEBUG = re.compile(
        r"TracerPid|isDebuggerConnected|JDWP|ro\.debuggable|"
        r"anti.?debug|tamper",
        re.IGNORECASE)

    def analyze(self, event: dict) -> list[str]:
        raw = event.get("d", "{}")
        try:
            d   = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            d = {}
        cls = d.get("cls", "")
        msg = d.get("msg", "")
        combined = f"{cls} {msg}"
        suggestions = []

        if self._PINNING.search(combined):
            suggestions += [
                f"{C.Y}[!]{C.RS} TLS Certificate Pinning detected in: {C.BD}{cls}{C.RS}",
                f"    → Run with {C.BD}--tls-intercept{C.RS} to inject NSC config.",
                f"    → Use Burp Suite / mitmproxy on port {C.BD}8080{C.RS}.",
            ]
        if self._INTEGRITY.search(combined):
            suggestions += [
                f"{C.Y}[!]{C.RS} Integrity / License check detected: {C.BD}{cls}{C.RS}",
                f"    → Run with {C.BD}--patch integrity{C.RS} to stub these checks.",
            ]
        if self._ANTIDEBUG.search(combined):
            suggestions += [
                f"{C.Y}[!]{C.RS} Anti-debug / tamper detection in: {C.BD}{cls}{C.RS}",
                f"    → Add {C.BD}--patch integrity{C.RS} to disable root/debug checks.",
            ]
        return suggestions

# ──────────────────────────────────────────────────────────────────────────────
#  LiveConsole  –  real-time coloured event stream
# ──────────────────────────────────────────────────────────────────────────────
class LiveConsole:
    """
    Renders bridge events as they arrive, colour-coded by type.
    Also feeds LearningEngine and ExceptionAnalyzer in parallel.
    Thread-safe: on_event() is called from BridgeServer worker threads.
    """

    _TAG_COLOR = {
        "NET": C.CY,
        "LC":  C.G,
        "ST":  C.M,
        "EX":  C.R,
    }
    _TAG_LABEL = {
        "NET": "NET ",
        "LC":  "LIFE",
        "ST":  "STOR",
        "EX":  "EXC ",
    }

    def __init__(self, learn_engine: "LearningEngine | None" = None,
                 exc_analyzer: "ExceptionAnalyzer | None" = None):
        self.learn   = learn_engine
        self.exc     = exc_analyzer
        self._lock   = threading.Lock()
        self._counts: dict[str, int] = defaultdict(int)

    def on_event(self, event: dict):
        tag  = event.get("t", "?")
        raw  = event.get("d", "{}")
        ts_f = event.get("_ts", time.time())
        ts   = time.strftime("%H:%M:%S", time.localtime(ts_f))
        color = self._TAG_COLOR.get(tag, C.W)
        label = self._TAG_LABEL.get(tag, tag)

        try:
            d = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            d = {}

        with self._lock:
            self._counts[tag] += 1
            if tag == "NET":
                url    = d.get("url", raw)
                method = d.get("m", "?")
                status = d.get("s", "?")
                # Colour status: green for 2xx, yellow for 3xx/4xx, red for 5xx
                s_col = (C.G if str(status).startswith("2") else
                         C.R if str(status).startswith("5") else C.Y)
                print(f"{C.CY}{ts}{C.RS} {color}[{label}]{C.RS} "
                      f"{C.BD}{method:6s}{C.RS} {url[:70]}  "
                      f"{s_col}{status}{C.RS}")

            elif tag == "LC":
                cls = d.get("cls", "?")
                ev  = d.get("ev", "?")
                is_sensitive = ev.startswith("SENSITIVE:")
                ev_col = C.Y if is_sensitive else C.G
                print(f"{C.CY}{ts}{C.RS} {color}[{label}]{C.RS} "
                      f"{cls[:50]}  {ev_col}{ev}{C.RS}")

            elif tag == "ST":
                typ = d.get("type", "?")
                key = d.get("key", "?")
                val = d.get("val", "?")[:40]
                print(f"{C.CY}{ts}{C.RS} {color}[{label}]{C.RS} "
                      f"[{typ}] {C.BD}{key}{C.RS} = {val}")

            elif tag == "EX":
                cls = d.get("cls", "?")
                msg = d.get("msg", "?")[:60]
                print(f"{C.CY}{ts}{C.RS} {color}[{label}]{C.RS} "
                      f"{C.BD}{cls}{C.RS}: {msg}")
                if self.exc:
                    for hint in self.exc.analyze(event):
                        print(f"         {hint}")
            else:
                print(f"{C.CY}{ts}{C.RS} {color}[{tag}]{C.RS} {raw[:80]}")

        # Feed learning engine (outside lock to avoid blocking console)
        if self.learn:
            self.learn.on_event(event)

    def print_stats(self):
        log("ok", "Event totals this session:")
        for tag, label in self._TAG_LABEL.items():
            n = self._counts.get(tag, 0)
            log("ok", f"  [{label}]: {n}", indent=1)

# ──────────────────────────────────────────────────────────────────────────────
#  HybridEngine  –  orchestrates learn → static-patch pipeline
# ──────────────────────────────────────────────────────────────────────────────
class HybridEngine:
    """
    Coordinates the three-phase hybrid workflow:

      Phase A  (--learn)  : static patch + instrumentation → observe → save profile
      Phase B  (--hybrid) : load profile → generate extra static patches → rebuild

    The two phases are intentionally separate CLI invocations so the developer
    can run the app multiple times / across different user flows before committing.
    """

    def __init__(self, cfg: RuntimeConfig):
        self.cfg = cfg

    def load_rules(self) -> list[dict]:
        """Load rules from rules_file (written by a previous --learn run)."""
        rf = self.cfg.rules_file
        if not os.path.isfile(rf):
            log("warn", f"Hybrid: rules file not found: {rf}.  "
                "Run --learn first.")
            return []
        try:
            with open(rf, encoding="utf-8") as fh:
                data = json.load(fh)
            rules = data.get("rules", [])
            log("ok", f"Hybrid: loaded {len(rules)} rule(s) from {rf}")
            return rules
        except Exception as e:
            log("err", f"Hybrid: cannot parse {rf}: {e}")
            return []

    def print_loaded_rules(self, rules: list[dict]):
        if not rules:
            return
        log("head", "Hybrid Rules")
        for r in rules:
            pat    = r.get("url_pattern", "?")
            atype  = r.get("action", {}).get("type", "?")
            source = r.get("source", "?")
            log("ok", f"  [{atype:12s}]  {pat[:60]}  [{source}]")

# ──────────────────────────────────────────────────────────────────────────────
#  Helper: print post-build ADB instructions for runtime modes
# ──────────────────────────────────────────────────────────────────────────────
def _print_runtime_instructions(cfg: RuntimeConfig, final_apk: str | None):
    log("head", "Runtime Analysis – Next Steps")
    apk = final_apk or "<patched.apk>"
    port = cfg.bridge_port

    if cfg.tls_intercept:
        log("info", "TLS Intercept mode:")
        log("info", f"  1. Start mitmproxy/Burp on port {cfg.proxy_port}", indent=1)
        log("info", "  2. On the device, set Wi-Fi proxy to 127.0.0.1:"
            f"{cfg.proxy_port}", indent=1)
        log("info", "  3. Install the proxy CA cert as a User certificate.", indent=1)
        log("info", "  4. Patched NSC config trusts user CAs automatically.", indent=1)

    if cfg.needs_bridge:
        log("info", "Bridge (APK → UnGuard event stream):")
        log("info", f"  1. Forward bridge port:  adb forward tcp:{port} tcp:{port}", indent=1)
        log("info", f"  2. Install patched APK:  adb install -r \"{apk}\"", indent=1)
        log("info", f"  3. Launch the app and interact.", indent=1)
        log("info", f"  4. Events stream live to this console.", indent=1)
        if cfg.learn:
            log("info",
                f"  5. Press Ctrl+C when done. Profile saved to: {cfg.profile_db}",
                indent=1)
            log("info",
                f"  6. Rules file: {cfg.rules_file}  (use with --hybrid next run)",
                indent=1)

    if not cfg.needs_bridge and not cfg.tls_intercept:
        log("info", "Static-only mode: install and run the patched APK normally.")
        log("info", f"  adb install -r \"{apk}\"", indent=1)


# ── Helper: resolve --smali-file argument ─────────────────────────────────────
def _resolve_smali_files(raw: str) -> list[str]:
    import glob
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    result = []
    seen   = set()
    for tok in tokens:
        matches = glob.glob(tok, recursive=True)
        if not matches:
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
            f"{C.BD}UnGuard v{TOOL_VERSION}{C.RS} – Android APK Patcher\n\n"
            f"Modes:\n"
            f"  {C.BD}APK mode{C.RS}        Pass an APK/AAB/APKS file as positional argument.\n"
            f"  {C.BD}Smali mode{C.RS}      Use --smali-file to patch .smali files directly.\n\n"
            f"Patch categories:\n{cats}\n\n"
            f"  {C.BD}all{C.RS}           All of the above in one build\n\n"
            f"Combine with comma, pipe, or space: iap,integrity,ads"
        ),
        epilog=(
            "Env-vars: APKTOOL_JAR KEYSTORE KEY_ALIAS KEY_PASS\n"
            "          ZIPALIGN APKSIGNER BUNDLETOOL MAX_WORKERS CACHE_MAX_MB\n\n"
            "APK mode examples:\n"
            "  python unguard.py app.apk --patch iap,integrity\n"
            "  python unguard.py app.apk --patch ads,iap,integrity\n"
            "  python unguard.py app.apk --patch all\n"
            "  python unguard.py app.apk --patch iap|ads\n"
            "  python unguard.py app.apk --detect-only\n"
            "  python unguard.py app.apk --patch iap --no-sign\n"
            "  python unguard.py app.apk --patch all -o ./out\n"
            "  python unguard.py app.apk --patch all --report out/report.json\n\n"
            "Smali file mode examples:\n"
            "  python unguard.py --smali-file BillingManager.smali --patch iap\n"
            "  python unguard.py --smali-file A.smali,B.smali,C.smali --patch all\n"
            "  python unguard.py --smali-file smali/*.smali --patch iap,ads\n"
            "  python unguard.py --smali-file Pay.smali --patch iap -o ./out\n\n"
        "Runtime analysis examples:\n"
        "  python unguard.py app.apk --patch all --net-debug\n"
        "  python unguard.py app.apk --patch all --trace-runtime\n"
        "  python unguard.py app.apk --patch all --tls-intercept\n"
        "  python unguard.py app.apk --patch all --learn\n"
        "  python unguard.py app.apk --patch all --hybrid\n"
        "  python unguard.py app.apk --patch all --learn --net-debug\n"
        "  python unguard.py app.apk --patch all --hybrid --tls-intercept\n"
        "  (bridge port) adb forward tcp:17185 tcp:17185\n"
        ),
    )

    parser.add_argument("target", nargs="?", default=None,
        help="APK / AAB / APKS / APKX / XAPK / ZIP file  (omit when using --smali-file)")

    pg = parser.add_argument_group("Patch selection")
    pg.add_argument(
        "--patch", metavar="CATS", default=None,
        help=(
            "Comma/pipe-separated patch categories.\n"
            "  iap, integrity, ads, storageIO, serverIO, all\n"
            "  Examples: --patch iap,integrity   --patch all   --patch iap|ads\n"
            "  Required unless --detect-only."
        ),
    )

    sf_group = parser.add_argument_group("Smali file mode  (no APK / apktool needed)")
    sf_group.add_argument(
        "--smali-file", metavar="FILES", default=None, dest="smali_file",
        help=(
            "One or more .smali files to scan and patch directly.\n"
            "  Comma-separated: --smali-file A.smali,B.smali\n"
            "  Glob patterns:   --smali-file smali/*.smali"
        ),
    )

    og = parser.add_argument_group("Output")
    og.add_argument("-o","--output", default=None, metavar="DIR",
        help="Output directory (APK or smali mode)")
    og.add_argument("--work-dir", default=None, metavar="DIR",
        help="Override temp workspace directory (APK mode only)")
    og.add_argument("--report", default=None, metavar="FILE",
        help="Write structured JSON patch report to FILE (APK mode)")

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

    rg = parser.add_argument_group(
        "Runtime analysis  (optional – inject bridge + activate subsystems)")
    rg.add_argument("--trace-runtime", action="store_true",
        help="Inject lifecycle + sensitive-method hooks; stream events live.")
    rg.add_argument("--tls-intercept", action="store_true",
        help="Disable certificate pinning via NSC injection. "
             "Use with Burp/mitmproxy on --proxy-port.")
    rg.add_argument("--learn", action="store_true",
        help="Observe app behaviour and save a profile to --profile-db. "
             "Auto-discovers premium gates, analytics, storage tokens.")
    rg.add_argument("--hybrid", action="store_true",
        help="Apply rules from a previous --learn session as static patches.")
    rg.add_argument("--net-debug", action="store_true",
        help="Stream all OkHttp network requests/responses to console.")
    rg.add_argument("--bridge-port", type=int, default=17185, metavar="PORT",
        help="TCP port for the APK→UnGuard event bridge. "
             "Default 17185. Run: adb forward tcp:PORT tcp:PORT")
    rg.add_argument("--proxy-port", type=int, default=8080, metavar="PORT",
        help="Local proxy port for TLS intercept (mitmproxy/Burp). Default 8080.")
    rg.add_argument("--profile-db", default="unguard_profile.db", metavar="FILE",
        help="SQLite profile database path (--learn / --hybrid).")
    rg.add_argument("--rules-file", default="unguard_rules.json", metavar="FILE",
        help="JSON rules file path (--learn writes, --hybrid reads).")

    args = parser.parse_args()

    # ── Apply global overrides ─────────────────────────────────────────────────
    if args.apktool:   APKTOOL_JAR = args.apktool
    if args.keystore:  KEYSTORE    = args.keystore
    if args.alias:     KEY_ALIAS   = args.alias
    if args.password:  KEY_PASS    = args.password
    if args.workers:   MAX_WORKERS = args.workers
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

        if args.detect_only:
            patches = frozenset()

        log("ok", f"Smali file mode: {len(smali_paths)} file(s)")
        log("ok", f"Patch selection: {C.BD}{patches_to_label(patches) if patches else 'scan only'}{C.RS}")

        sfp = SmaliFilePatcher(patches=patches, output_dir=args.output)
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

    # ── Build RuntimeConfig from optional runtime flags ─────────────────────
    rt_cfg = RuntimeConfig(
        trace_runtime = getattr(args, "trace_runtime", False),
        tls_intercept = getattr(args, "tls_intercept", False),
        learn         = getattr(args, "learn",         False),
        hybrid        = getattr(args, "hybrid",        False),
        net_debug     = getattr(args, "net_debug",     False),
        bridge_port   = getattr(args, "bridge_port",   17185),
        proxy_port    = getattr(args, "proxy_port",    8080),
        profile_db    = getattr(args, "profile_db",    "unguard_profile.db"),
        rules_file    = getattr(args, "rules_file",    "unguard_rules.json"),
    )
    if rt_cfg.any_runtime:
        active = [f for f in ("trace_runtime","tls_intercept","learn",
                               "hybrid","net_debug") if getattr(rt_cfg, f)]
        log("ok",
            f"Runtime modules active: {C.BD}{', '.join(active)}{C.RS}")
    if rt_cfg.hybrid and not os.path.isfile(rt_cfg.rules_file):
        log("warn",
            f"--hybrid set but rules file not found: {rt_cfg.rules_file}. "
            "Run --learn first to generate it.")

    patcher = AndroidPatcher(
        target      = args.target,
        output_dir  = args.output or ".",
        work_dir    = args.work_dir,
        skip_sign   = args.no_sign,
        skip_deob   = args.no_deob,
        workers     = MAX_WORKERS,
        runtime_cfg = rt_cfg,
    )

    ok = False
    try:
        results = patcher.run(
            patches     = patches,
            detect_only = args.detect_only,
            report_path = args.report,
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
