#!/usr/bin/env python3
# unguard.py
"""
UnGuard v3.3.1 – Hybrid Static + Runtime Analysis
========================
Detect · Deobfuscate · Patch · Rebuild · Sign

New in v3.3.1:
  --fake-google-verify  : Intercept Google validation requests (licensing, purchase verify)
                           and return a hardcoded success response without contacting Google.
                           Works together with --tls-intercept.

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
TOOL_VERSION = "3.3.1"
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

    # Throttle redraws: no faster than every 80 ms (avoids burst interleaving)
    _DRAW_INTERVAL = 0.08

    def _draw(self, n: int):
        now = time.monotonic()
        # Throttle: skip if drawn too recently (except on 0% and 100%)
        pct = min(n / self.total, 1.0)
        with self._lock:
            last = getattr(self, "_last_draw", 0.0)
            if pct not in (0.0, 1.0) and (now - last) < self._DRAW_INTERVAL:
                return
            object.__setattr__(self, "_last_draw", now)
        filled = int(self.BAR_W * pct)
        bar    = C.G + "█" * filled + C.CY + "░" * (self.BAR_W - filled) + C.RS
        ts     = time.strftime("%H:%M:%S")
        # \033[2K erases entire line; \r returns to column 0 without newline.
        # On Termux we also check if stdout is a real tty.
        if sys.stdout.isatty():
            line = (f"\033[2K\r{C.CY}{ts}{C.RS} {C.CY}[~]{C.RS} "
                    f"{self.label}  [{bar}] "
                    f"{C.BD}{n}/{self.total}{C.RS} ({pct:.0%})")
        else:
            # Non-tty (piped / redirected): print on new line at 0/25/50/75/100%
            thresholds = {0, 25, 50, 75, 100}
            if int(pct * 100) not in thresholds:
                return
            line = (f"\n{C.CY}{ts}{C.RS} {C.CY}[~]{C.RS} "
                    f"{self.label}  {int(pct*100):3d}%  {n}/{self.total}")
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
  |  UnGuard v3.3.1  Hybrid Analysis Framework                 |
  |  --patch all  --trace-runtime  --tls-intercept  --learn   |
  |  --fake-google-verify                                       |
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
#  SmaliAST  –  Structured Smali Parser
#
#  Replaces raw-regex line scanning for structural decisions (method boundaries,
#  return types, parameter counts, field names) where regex gives false positives
#  from string literals and commented-out code.
#
#  Design:  one-pass O(N) line scanner → dataclass tree.
#           No backtracking, no external dependencies.
#           Regex is still used for CONTENT matching (find IAP signatures etc.)
#           but SmaliAST owns STRUCTURE parsing (what IS a method, what IS its
#           return type, how many params does it take).
# ──────────────────────────────────────────────────────────────────────────────
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

@_dc
class SmaliInstr:
    """A single smali instruction or directive (non-blank, non-pure-comment)."""
    line_no  : int          # 0-based index into the source line list
    opcode   : str          # first token: invoke-virtual, const/4, .line, :label…
    raw      : str          # full stripped line content

@_dc
class SmaliMethod:
    """One .method … .end method block."""
    line_start  : int                   # index of ".method …" line
    line_end    : int                   # index of ".end method" line
    declaration : str                   # full declaration text (stripped)
    name        : str                   # method name (before "(")
    descriptor  : str                   # full JVM descriptor e.g. "(IZ)V"
    return_type : str                   # return type e.g. "V","Z","I","Ljava/…;"
    is_static   : bool
    is_abstract : bool
    is_native   : bool
    param_count : int                   # number of JVM parameter slots
    locals_n    : int                   # value of .locals directive (−1 if absent)
    locals_line : int                   # index of .locals line (−1 if absent)
    instrs      : list["SmaliInstr"]    # non-blank, non-comment instruction lines

@_dc
class SmaliField:
    """A .field declaration."""
    line_no     : int
    declaration : str
    name        : str
    type_       : str

@_dc
class SmaliClass:
    """Top-level parsed representation of one .smali file."""
    path        : str                   # filesystem path
    class_decl  : str                   # ".class …" line
    super_decl  : str                   # ".super …" line
    class_name  : str                   # Lfoo/Bar;
    super_name  : str                   # Ljava/lang/Object;
    implements  : list[str]             # list of Lfoo/Iface;
    fields      : list[SmaliField]
    methods     : list[SmaliMethod]
    source_lines: list[str]             # original readlines() content (mutable)

# ── JVM descriptor helpers ────────────────────────────────────────────────────
_PRIM_WIDTHS = {
    "J": 2, "D": 2,   # long, double occupy two register slots
    "B": 1, "C": 1, "F": 1, "I": 1, "S": 1, "Z": 1,
}

def _count_jvm_params(descriptor: str) -> int:
    """Count JVM parameter register slots from a method descriptor.
    Longs and doubles each use 2 slots; everything else uses 1."""
    if "(" not in descriptor or ")" not in descriptor:
        return 0
    params_str = descriptor[descriptor.index("(")+1 : descriptor.rindex(")")]
    count = 0
    i = 0
    while i < len(params_str):
        c = params_str[i]
        if c == "L":
            j = params_str.index(";", i)
            count += 1; i = j + 1
        elif c == "[":
            # array – skip dimension chars, then the element type
            while i < len(params_str) and params_str[i] == "[":
                i += 1
            if i < len(params_str):
                if params_str[i] == "L":
                    j = params_str.index(";", i)
                    i = j + 1
                else:
                    i += 1
            count += 1
        elif c in _PRIM_WIDTHS:
            count += _PRIM_WIDTHS[c]; i += 1
        else:
            i += 1
    return count

def _return_type_from_descriptor(descriptor: str) -> str:
    """Extract the return type from a JVM method descriptor."""
    if ")" not in descriptor:
        return "V"
    return descriptor[descriptor.rindex(")") + 1:]

# ── One-pass parser ───────────────────────────────────────────────────────────
_CLASS_RE   = re.compile(r"\.class\s+(.*?)\s+(L[^;]+;)")
_SUPER_RE   = re.compile(r"\.super\s+(L[^;]+;)")
_IMPL_RE    = re.compile(r"\.implements\s+(L[^;]+;)")
_FIELD_RE   = re.compile(r"\.field\s+(.*?)\s+(\w+):(.*)")
_METHOD_RE  = re.compile(
    r"\.method\s+((?:(?:public|private|protected|static|final|"
    r"synchronized|bridge|varargs|synthetic|abstract|native|transient)\s+)*)([^(]+)(\([^)]*\).*)"
)
_LOCALS_RE  = re.compile(r"[ \t]+\.locals\s+(\d+)")
_OPCODE_RE  = re.compile(r"^\s+([a-z][\w/-]*)\s*")

def parse_smali(path: str, source: _Opt[list[str]] = None) -> _Opt[SmaliClass]:
    """
    Parse a .smali file into a SmaliClass AST.

    Parameters
    ----------
    path   : filesystem path to the .smali file
    source : pre-loaded list of lines (avoids a second read if already cached)

    Returns None on parse error.
    """
    if source is None:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                source = fh.readlines()
        except Exception:
            return None

    cls_name = super_name = class_decl = super_decl = ""
    implements: list[str] = []
    fields:  list[SmaliField]  = []
    methods: list[SmaliMethod] = []

    in_method    = False
    m_start      = -1
    m_decl       = ""
    m_name       = ""
    m_desc       = ""
    m_is_static  = False
    m_is_abstract= False
    m_is_native  = False
    m_locals_n   = -1
    m_locals_ln  = -1
    m_instrs: list[SmaliInstr] = []

    in_annotation = 0    # nesting counter for .annotation … .end annotation

    for i, raw in enumerate(source):
        stripped = raw.strip()

        # Skip blank lines and pure comments everywhere
        if not stripped or stripped.startswith("#"):
            continue

        # Annotation blocks – skip content (multi-line directives that can
        # contain fake-looking method names or class references)
        if stripped.startswith(".annotation"):
            in_annotation += 1
            continue
        if stripped.startswith(".end annotation"):
            in_annotation = max(0, in_annotation - 1)
            continue
        if in_annotation:
            continue

        first = stripped.split()[0] if stripped.split() else ""

        # ── Top-level directives (outside method) ─────────────────────────
        if not in_method:
            if first == ".class":
                class_decl = stripped
                m2 = _CLASS_RE.search(stripped)
                if m2:
                    cls_name = m2.group(2)
            elif first == ".super":
                super_decl = stripped
                m2 = _SUPER_RE.search(stripped)
                if m2:
                    super_name = m2.group(1)
            elif first == ".implements":
                m2 = _IMPL_RE.search(stripped)
                if m2:
                    implements.append(m2.group(1))
            elif first == ".field":
                m2 = _FIELD_RE.search(stripped)
                if m2:
                    fields.append(SmaliField(
                        line_no=i, declaration=stripped,
                        name=m2.group(2), type_=m2.group(3).strip()))
            elif first == ".method":
                m2 = _METHOD_RE.search(stripped)
                if m2:
                    flags_str  = m2.group(1)
                    m_name     = m2.group(2).strip()
                    m_desc     = m2.group(3).strip()
                    m_is_static   = "static" in flags_str
                    m_is_abstract = "abstract" in flags_str
                    m_is_native   = "native" in flags_str
                    m_start    = i
                    m_decl     = stripped
                    m_locals_n = m_locals_ln = -1
                    m_instrs   = []
                    in_method  = True

        else:
            # ── Inside a method ───────────────────────────────────────────
            if first == ".end" and (stripped == ".end method"
                                   or stripped.startswith(".end method ")):
                # Allow trailing comments: ".end method # generated" etc.
                # Finalise method
                ret_type = _return_type_from_descriptor(m_desc)
                param_slots = _count_jvm_params(m_desc)
                methods.append(SmaliMethod(
                    line_start  = m_start,
                    line_end    = i,
                    declaration = m_decl,
                    name        = m_name,
                    descriptor  = m_desc,
                    return_type = ret_type,
                    is_static   = m_is_static,
                    is_abstract = m_is_abstract,
                    is_native   = m_is_native,
                    param_count = param_slots,
                    locals_n    = m_locals_n,
                    locals_line = m_locals_ln,
                    instrs      = m_instrs,
                ))
                in_method = False
            elif first == ".locals":
                m2 = _LOCALS_RE.match(raw)
                if m2:
                    m_locals_n  = int(m2.group(1))
                    m_locals_ln = i
                m_instrs.append(SmaliInstr(line_no=i, opcode=first, raw=stripped))
            elif first.startswith(":"):
                # label – record but mark as label
                m_instrs.append(SmaliInstr(line_no=i, opcode=first, raw=stripped))
            elif first.startswith("."):
                # sub-directives (.line, .param, .restart local, .catch, …)
                m_instrs.append(SmaliInstr(line_no=i, opcode=first, raw=stripped))
            else:
                # Real instruction
                m2 = _OPCODE_RE.match(raw)
                opcode = m2.group(1) if m2 else first
                m_instrs.append(SmaliInstr(line_no=i, opcode=opcode, raw=stripped))

    if not cls_name:
        return None   # not a valid smali file

    return SmaliClass(
        path         = path,
        class_decl   = class_decl,
        super_decl   = super_decl,
        class_name   = cls_name,
        super_name   = super_name,
        implements   = implements,
        fields       = fields,
        methods      = methods,
        source_lines = source,
    )


def smali_method_has_sig(method: SmaliMethod, sig: str) -> bool:
    """Return True if ANY instruction in the method body contains sig.
    Unlike regex on raw text this ONLY searches actual instructions –
    not string literal arguments, not comments, not annotation values."""
    return any(sig in instr.raw for instr in method.instrs)


def smali_find_methods_by_name(cls: SmaliClass, name_pattern: str) -> list[SmaliMethod]:
    """Return methods whose name matches a compiled-regex pattern."""
    pat = re.compile(name_pattern)
    return [m for m in cls.methods if pat.search(m.name)]


def smali_find_methods_containing(cls: SmaliClass, sig: str) -> list[SmaliMethod]:
    """Return methods that reference sig anywhere in their instructions."""
    return [m for m in cls.methods if smali_method_has_sig(m, sig)]


def smali_locals_safe_to_bump(method: SmaliMethod, by: int = 2) -> bool:
    """
    Return True if bumping .locals by `by` is safe.
    Unsafe if:
      - new count > 250 (dexlib2 cap)
      - registers v{old_n}..v{old_n+by-1} already appear in the method body
        (they may be parameter aliases inserted by an obfuscator)
    """
    if method.is_abstract or method.is_native:
        return False
    old_n = method.locals_n
    if old_n < 0:
        return False
    if old_n + by > 250:
        return False
    new_regs = set(range(old_n, old_n + by))
    body_text = " ".join(instr.raw for instr in method.instrs)
    for r in new_regs:
        if re.search(r"\bv" + str(r) + r"\b", body_text):
            return False
    return True


def smali_bump_locals(method: SmaliMethod, source_lines: list[str],
                      by: int = 2) -> _Opt[int]:
    """
    Bump .locals in source_lines by `by` and return the index of the first
    new free register (old_n). Returns None if unsafe or .locals not found.
    """
    if not smali_locals_safe_to_bump(method, by):
        return None
    ll = method.locals_line
    if ll < 0:
        return None
    old_n = method.locals_n
    # Patch the actual source line
    source_lines[ll] = re.sub(
        r"([ \t]+\.locals\s+)(\d+)",
        lambda m2: f"{m2.group(1)}{old_n + by}",
        source_lines[ll], count=1)
    return old_n   # caller uses v{old_n} and v{old_n+by-1} as free registers

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

    # Directories that never contain smali files – skip entirely
    _SKIP_DIRS = frozenset({"res", "assets", "lib", "libs", "unknown",
                             "original", "kotlin", "META-INF"})

    def load(self, show_progress: bool = True):
        if self._loaded:
            return
        t0 = time.time()
        all_files = []
        for root, dirs, files in os.walk(str(self.base)):
            # Prune non-smali dirs in-place so os.walk doesn't descend into them
            rel_root = os.path.relpath(root, str(self.base))
            if rel_root == ".":
                dirs[:] = [d for d in dirs if d not in self._SKIP_DIRS]
            for fname in files:
                if fname.endswith(".smali"):
                    all_files.append(os.path.join(root, fname))
        total   = len(all_files)
        cap_b   = CACHE_MAX_MB * 1024 * 1024
        used_b  = 0
        pb      = Progress("Loading smali", total) if show_progress and total > 50 else None
        capped  = 0

        # Parallel read: use a thread pool to read all files concurrently.
        # On Termux (ARM, slow eMMC) this gives 2-4x speedup over sequential.
        def _read(full):
            try:
                return Path(full).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return ""

        rels = [os.path.relpath(f, str(self.base)) for f in all_files]
        self._all_rels = rels[:]

        # Only parallel-read up to the cap; beyond it we read on-demand.
        # Determine how many files fit in the cap by estimated average size.
        # Use a conservative 8 KB average – real smali averages 2-6 KB.
        est_files_in_cap = min(total, max(1, int(cap_b // 8192)))

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(_read, all_files[i]): i
                    for i in range(min(est_files_in_cap, total))}
            done = 0
            for fut in as_completed(futs):
                idx_f = futs[fut]
                rel   = rels[idx_f]
                try:
                    content = fut.result()
                except Exception:
                    content = ""
                size = len(content.encode("utf-8", errors="ignore"))
                if used_b + size <= cap_b:
                    self._data[rel] = content
                    used_b += size
                else:
                    capped += 1
                done += 1
                if pb and (done % 200 == 0 or done == total):
                    pb.update(done)

        # Any files beyond est_files_in_cap are on-demand only
        for i in range(est_files_in_cap, total):
            capped += 1
            if pb:
                pb.update(min(est_files_in_cap + 1, total))
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

        Optimisations over the naive approach:
          1. Early-exit per tag: once a file matches the first pattern for a
             given tag it is recorded and that tag is skipped for the rest of
             the file.  A billing file with 40 gplay patterns only checks the
             first one that matches.
          2. submit()+as_completed(): progress advances as ANY file finishes,
             not in submission order.  Prevents apparent hangs on giant IL2CPP
             files.
          3. Pre-compile all regexes once before dispatching workers.
        """
        # Group patterns by tag so we can early-exit per tag
        from collections import defaultdict as _dd
        tag_pats: dict[str, list] = _dd(list)
        for p, t in patterns:
            tag_pats[t].append(re.compile(p, re.IGNORECASE))
        tag_order = list(tag_pats.keys())

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
            hits = []
            for tag in tag_order:
                for pat in tag_pats[tag]:
                    if pat.search(text):
                        hits.append((tag, rel))
                        break          # ← early-exit: one match per tag per file
            return hits

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
                if pb and (done % 100 == 0 or done == total):
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
    """Write lines to path atomically via mkstemp + os.replace (crash-safe).
    On Windows, os.replace may raise PermissionError if the target file is
    momentarily open (e.g. antivirus scan). Retry once after 50 ms."""
    dir_ = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".ug_tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
        except Exception:
            try: os.unlink(tmp)
            except Exception: pass
            raise
        # Retry with exponential backoff (Windows AV / file-lock races)
        delay = 0.05
        for _attempt in range(4):
            try:
                os.replace(tmp, path)
                return True
            except PermissionError:
                if _attempt == 3:
                    raise
                time.sleep(delay)
                delay *= 2
        return True   # unreachable but satisfies type checker
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
                           lookahead: int = 64) -> int | None:
    """
    Return the line index of the next move-result(-object|-wide) after from_idx.

    Skips blank lines, comments, .line directives, labels, and nop instructions.
    Stops at the first REAL instruction that is not move-result.

    lookahead=64: aggressive obfuscators (DexGuard, Arxan) inject 30-50 .line
    directives between invoke and move-result. We use instruction-counting rather
    than line-counting: we stop when we see a non-move-result real instruction,
    regardless of how many non-code lines we passed. The lookahead only caps the
    absolute line window as a safety net against infinite loops.
    """
    real_instrs_seen = 0
    for j in range(from_idx + 1, min(from_idx + 1 + lookahead, len(lines))):
        s = lines[j].strip()
        if not s or s.startswith("#"):
            continue                        # blank / comment – skip
        if re.match(r"move-result(?:-object|-wide)?\s+[vp]\d+", s):
            return j                        # found it
        if _NON_CODE_RE.match(lines[j]):
            continue                        # .line / label / directive – skip
        if s == "nop":
            continue                        # nop is harmless
        # Real instruction that is NOT move-result
        real_instrs_seen += 1
        if real_instrs_seen >= 2:
            break   # two real instructions without finding move-result → give up
    return None

def _next_move_result(lines: list[str], from_idx: int,
                      lookahead: int = 32) -> str | None:
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
    v>15 guard: skip if source_reg is v16+ (const/4 uses 4-bit register field).
    """
    try:
        if source_reg.startswith("v") and int(source_reg[1:]) > 15:
            return 0
    except (ValueError, IndexError):
        pass
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
                # Skip if dest > v15 (const/4 is 4-bit)
                try:
                    if dest.startswith("v") and int(dest[1:]) > 15:
                        i += 1; continue
                except (ValueError, IndexError):
                    pass
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

def _verify_dex_contains_patches(apk_path: str) -> bool:
    """
    Open the rebuilt APK as a ZIP, extract the string table from each DEX,
    and check that at least one UNGUARD string exists.
    This catches the case where apktool compiled from the wrong directory
    and the patches never made it into the final bytecode.
    Returns True if verified (or if APK cannot be opened – don't block).
    """
    try:
        import zipfile as _zf, struct as _st
        with _zf.ZipFile(apk_path, "r") as z:
            dex_names = [n for n in z.namelist() if n.endswith(".dex")]
            for dex_name in dex_names:
                data = z.read(dex_name)
                if len(data) < 0x70:
                    continue
                # Read string table
                str_ids_size = _st.unpack_from("<I", data, 0x38)[0]
                str_ids_off  = _st.unpack_from("<I", data, 0x3c)[0]
                for idx in range(min(str_ids_size, 80000)):
                    off = _st.unpack_from("<I", data, str_ids_off + idx * 4)[0]
                    p = off
                    length = 0; shift = 0
                    while p < len(data):
                        b = data[p]; p += 1
                        length |= (b & 0x7f) << shift
                        if not (b & 0x80): break
                        shift += 7
                    if length < 6 or p + length > len(data):
                        continue
                    try:
                        s = data[p:p + length].decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    # "UNGUARD" comments are stripped at compile time.
                    # Look for strings that our patches ACTUALLY inject into bytecode:
                    # - "unguard"  from purchaseToken in const-string
                    # - "bypass"   from productId in const-string  
                    # - "com/ug/rt" from runtime bridge class refs
                    sl = s.lower()
                    if (sl == "unguard" or sl == "bypass"
                            or "com/ug/rt" in s
                            or s == "purchaseToken"):
                        return True
    except Exception:
        pass  # Verification is best-effort; never block the pipeline
    return False

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
        # ── Google Play Billing v3-v6 ─────────────────────────────────────────
        (r"Lcom/android/billingclient/api/BillingClient;",                     "gplay"),
        (r"Lcom/android/billingclient/api/PurchasesUpdatedListener;",          "gplay"),
        (r"Lcom/android/billingclient/api/ProductDetails;",                    "gplay"),
        (r"Lcom/android/billingclient/api/BillingFlowParams;",                 "gplay"),
        (r"Lcom/android/billingclient/api/ConsumeParams;",                     "gplay"),
        (r"Lcom/android/billingclient/api/Purchase;",                          "gplay"),
        (r"Lcom/android/billingclient/api/BillingResult;",                     "gplay"),
        (r"Lcom/android/billingclient/api/QueryProductDetailsParams;",         "gplay"),
        (r"Lcom/android/billingclient/api/BillingClient\$Builder;",           "gplay"),
        (r"Lcom/android/billingclient/api/AcknowledgePurchaseParams;",         "gplay"),
        (r"->launchBillingFlow",                                               "gplay"),
        (r"->queryProductDetailsAsync",                                        "gplay"),
        (r"->acknowledgePurchase",                                             "gplay"),
        (r"->consumeAsync",                                                    "gplay"),
        (r"->startConnection",                                                 "gplay"),
        (r"->isReady\(\)",                                                    "gplay"),
        (r"->endConnection",                                                   "gplay"),
        (r"->queryPurchasesAsync",                                             "gplay"),
        # ── Google Pay (wallet / payment token API) ───────────────────────────
        (r"Lcom/google/android/gms/wallet/",                                   "gpay"),
        (r"Lcom/google/android/gms/wallet/PaymentsClient;",                    "gpay"),
        (r"Lcom/google/android/gms/wallet/IsReadyToPayRequest;",               "gpay"),
        (r"Lcom/google/android/gms/wallet/PaymentDataRequest;",                "gpay"),
        (r"->isReadyToPay\(",                                                  "gpay"),
        (r"->loadPaymentData\(",                                               "gpay"),
        # ── Subscriptions v6+ ─────────────────────────────────────────────────
        (r"Lcom/android/billingclient/api/SubscriptionUpdateParams;",          "gplay_v6"),
        (r"Lcom/android/billingclient/api/ProductDetailsResponseListener;",    "gplay_v6"),
        (r"Lcom/android/billingclient/api/PurchasesResponseListener;",         "gplay_v6"),
        # ── Amazon ───────────────────────────────────────────────────────────
        (r"Lcom/amazon/device/iap/PurchasingService;",                         "amazon"),
        (r"Lcom/amazon/device/iap/model/Receipt;",                             "amazon"),
        (r"Lcom/amazon/device/iap/PurchasingListener;",                        "amazon"),
        # ── Huawei ────────────────────────────────────────────────────────────
        (r"Lcom/huawei/hms/iap/IapClient;",                                    "huawei"),
        (r"Lcom/huawei/hms/iap/entity/InAppPurchaseData;",                     "huawei"),
        # ── Samsung / OneStore ────────────────────────────────────────────────
        (r"Lcom/samsung/android/iap/",                                         "samsung"),
        (r"Lcom/onestore/iap/",                                                "onestore"),
        # ── Generic premium gate methods ─────────────────────────────────────
        (r"isPremium|isSubscribed|hasPurchased|isPurchased",                   "generic"),
        (r"isEntitled|isLicensed|isPaid|isVip|isMember|isUnlocked",            "generic"),
        (r"PURCHASE_STATE_PURCHASED|purchaseState|purchaseToken",              "generic"),
        (r"purchase|billing|ProductDetails|SKU_DETAILS",                       "generic"),
        # ── BillingClientStateListener callbacks ─────────────────────────────
        (r"Lcom/android/billingclient/api/BillingClientStateListener;",        "billing_state"),
        (r"onBillingSetupFinished",                                             "billing_state"),
        (r"onBillingServiceDisconnected",                                       "billing_state"),
        # ── Unity billing bridge (WebViewStoreEventListener) ──────────────────
        # These files contain the if-ne gates that route to C# success/error.
        # Patching them makes the WebView receive PURCHASES_UPDATED_RESULT
        # regardless of what the billing result code actually was.
        (r"Lcom/unity3d/services/store/WebViewStoreEventListener;",            "unity_bridge"),
        (r"PURCHASES_UPDATED_RESULT|PURCHASES_UPDATED_ERROR",                  "unity_bridge"),
        (r"StoreWebViewEventSender",                                            "unity_bridge"),
        (r"Lcom/unity3d/services/store/gpbl/bridges/BillingResultBridge;",     "unity_bridge"),
        # ── BillingResult class – contains getResponseCode() ──────────────────
        (r"\.class.*Lcom/android/billingclient/api/BillingResult;",           "billing_result"),
        (r"getResponseCode\(\)I",                                             "billing_result"),
        (r"Lcom/android/billingclient/api/BillingResult;",                     "billing_result"),
        # ── ServiceConnection files – intercept binder injection point ────────
        # Files calling IInAppBillingService$Stub.asInterface() are where the
        # real Play Store binder is received. We replace it with FakeIAP binder.
        (r"IInAppBillingService.*asInterface",                                  "svc_conn"),
        (r"Lcom/android/vending/billing/IInAppBillingService",                 "svc_conn"),
        # ── Purchase state / acknowledgement ──────────────────────────────────
        (r"->getPurchaseState\(\)",                                            "purchase_state"),
        (r"getPurchaseState|PURCHASE_STATE_PURCHASED|PURCHASED",               "purchase_state"),
        (r"->isAcknowledged\(\)",                                             "purchase_state"),
    ]
    INTEGRITY_PATTERNS = [
        # ── Play Integrity API ────────────────────────────────────────────────
        (r"Lcom/google/android/play/core/integrity/IntegrityManager;",           "play_int"),
        (r"Lcom/google/android/play/core/integrity/IntegrityTokenResponse;",     "play_int"),
        (r"Lcom/google/android/play/core/integrity/StandardIntegrityManager;",   "play_int"),
        (r"Lcom/google/android/play/core/integrity/StandardIntegrityToken;",     "play_int"),
        (r"->requestIntegrityToken",                                              "play_int"),
        (r"->requestAndShowDialog",                                              "play_int"),
        # ── SafetyNet (deprecated but still widely used) ──────────────────────
        (r"Lcom/google/android/gms/safetynet/SafetyNet;",                        "safetynet"),
        (r"Lcom/google/android/gms/safetynet/SafetyNetApi;",                     "safetynet"),
        (r"->attest\(",                                                           "safetynet"),
        # ── Android Vending LVL (classic) ────────────────────────────────────
        (r"Lcom/android/vending/licensing/LicenseChecker;",                      "lvl"),
        (r"Lcom/android/vending/licensing/LicenseValidator;",                    "lvl"),
        (r"Lcom/google/android/vending/licensing/",                              "lvl2"),
        # ── PairIP (most common Unity game license system) ────────────────────
        (r"Lcom/pairip/licensecheck/LicenseClient;",                             "pairip"),
        (r"Lcom/pairip/licensecheck/LicenseActivity;",                           "pairip"),
        (r"Lcom/pairip/licensecheck/LicenseContentProvider;",                    "pairip"),
        (r"com/pairip/licensecheck",                                              "pairip"),
        (r"initializeLicenseCheck|scheduleRepeatedLicenseCheck|"
         r"reportSuccessfulLicenseCheck|populateInputDataForLicenseCheck",        "pairip"),
        # ── Kiwi Security ────────────────────────────────────────────────────
        (r"Lcom/kiwi/security/",                                                 "kiwi"),
        # ── AppSealing / DexProtector ─────────────────────────────────────────
        (r"Lcom/inka/android/appsealing/",                                       "appsealing"),
        (r"com/dexprotector/",                                                    "dexprotector"),
        # ── Signature / installer / package checks ────────────────────────────
        (r"->getPackageInfo",                                                     "sig"),
        (r"->signatures",                                                         "sig"),
        (r"->getInstallerPackageName",                                            "sig"),
        (r"->getInstallerPackageNameCompat",                                      "sig"),
        (r"->getSigningInfo",                                                     "sig"),
        (r"->signingInfo",                                                        "sig"),
        # ── Anti-tamper patterns ──────────────────────────────────────────────
        (r"isDatabaseIntegrityOk",                                               "dbint"),
        (r"WEBVIEW_MEDIA_INTEGRITY",                                             "wvint"),
        (r"checkValidity|verifyPurchase|validateReceipt|checkAppIntegrity",      "custom"),
        (r"tamperDetect|rootDetect|isRooted|isDebuggable",                       "antitamper"),
        # ── Subscription management SDKs (often gate features) ───────────────
        (r"Lcom/revenuecat/purchases/",                                          "revenuecat"),
        (r"Lcom/qonversion/android/sdk/",                                        "qonversion"),
        (r"Lio/adapty/sdk/",                                                     "adapty"),
        (r"Lcom/chargebee/android/",                                             "chargebee"),
        (r"Lcom/google/android/play/core/review/",                               "play_review"),
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
        # ── JSON parsing ─────────────────────────────────────────────────────
        (r"Lorg/json/JSONObject;->(?:getInt|optInt)\(",                           "json"),
        (r"Lorg/json/JSONObject;->(?:getBoolean|optBoolean)\(",                  "json"),
        (r"Lorg/json/JSONObject;->(?:getString|optString)\(",                    "json"),
        (r"Lorg/json/JSONObject;->(?:getLong|optLong)\(",                        "json"),
        (r"Lorg/json/JSONArray;->length\(",                                      "json"),
        # ── Retrofit2 ────────────────────────────────────────────────────────
        (r"Lretrofit2/Response;->(?:code|isSuccessful)\(",                       "retrofit"),
        (r"Lretrofit2/Call;->execute\(",                                         "retrofit"),
        # ── OkHttp3 ──────────────────────────────────────────────────────────
        (r"Lokhttp3/Response;->(?:code|isSuccessful)\(",                         "okhttp"),
        (r"Lokhttp3/ResponseBody;->string\(",                                    "okhttp"),
        # ── Ktor ─────────────────────────────────────────────────────────────
        (r"Lio/ktor/client/statement/HttpResponse;",                              "ktor"),
        # ── Volley ───────────────────────────────────────────────────────────
        (r"Lcom/android/volley/Response\$Listener;",                             "volley"),
        # ── Generic status keys ───────────────────────────────────────────────
        (r"purchaseState|statusCode|status_code|result_code|"
         r"resultCode|errorCode|error_code|responseCode",                         "status"),
        (r'"status"|"code"|"result"|"success"|"active"|"subscribed"',           "json_key"),
        (r'"premium"|"isPremium"|"licensed"|"valid"|"verified"',                "json_key"),
        # ── HttpURLConnection ─────────────────────────────────────────────────
        (r"Ljava/net/HttpURLConnection;->getResponseCode\(",                     "urlconn"),
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
        # ── Additional ad networks ────────────────────────────────────────────
        (r"Lcom/pubmatic/sdk/",                                            "pubmatic"),
        (r"Lcom/mintegral/",                                               "mintegral"),
        (r"Lcom/tradplus/",                                                "tradplus"),
        (r"Lcom/bidmachine/",                                              "bidmachine"),
        (r"Lai/admost/",                                                   "admost"),
        (r"Lnet/sourceforge/openads/",                                     "openads"),
        (r"Lcom/my/target/",                                               "mytarget"),
        (r"Lru/mail/",                                                     "vk_ads"),
        (r"Lcom/yandex/mobile/ads/",                                       "yandex_ads"),
        (r"Lbiz/growthcraft/",                                             "startapp"),
        (r"Lcom/startapp/sdk/",                                            "startapp"),
        (r"Lcom/inmobi/ads/",                                              "inmobi"),
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
        r"requestPurchase|buyProduct|orderProduct|"
        r"startPayment|requestPayment|initiatePayment|processPayment|"
        r"handlePayment|doPayment|startCheckout|"
        r"processCheckout|submitOrder|doPurchaseFlow)\("
        # NOTE: launchBillingFlow is intentionally NOT here.
        # Stubbing it to return null causes NPE when app calls getResponseCode()
        # on the null result. launchBillingFlow must run normally to show the
        # Play Store purchase UI. The response is handled by getResponseCode()=OK patch.
    )
    _BOOL_GATE_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:isPremium|isUnlocked|isPurchased|isSubscribed|hasPurchased|"
        r"checkPremium|isLicensed|isActivated|isProUser|isProVersion|"
        r"isFullVersion|isBought|hasFullAccess|isPaid|isVip|isVIP|"
        r"isPro|isActive|isMember|hasSubscription|isEntitled|"
        r"checkEntitlement|isVipMember|isPremiumUser|hasPremium|"
        r"isGoldMember|isPremiumMember|canAccess|isFeatureEnabled|"
        r"isContentUnlocked|hasPurchasedPremium|isReadyToPay|"
        r"canMakePayment|isBillingSupported|isSubscriptionSupported|"
        r"isReadyToPay|isBillingReady|isBillingAvailable|"
        r"isBillingSetupDone|isBillingClientReady)\(\)Z"
    )

    # Matches getResponseCode()I ONLY in billing-related classes.
    # Must be combined with a class-name check to avoid patching HTTP
    # response code getters (WebRequest.getResponseCode, HttpURLConnection, etc.)
    _BILLING_RESULT_GETTER_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"getResponseCode\(\)I"
    )
    # Class names that legitimately contain billing response codes
    _BILLING_CLASS_RE = re.compile(
        r"(?:BillingResult|BillingResponse|BillingStatus|InAppMessage|"
        r"BillingResultResponse|com/android/billingclient)",
        re.IGNORECASE
    )

    # FIX: Scoped integrity regex – requires class context before onFailure
    # to avoid matching unrelated listener/callback methods.
    _INTEGRITY_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"(?:requestIntegrityToken|attest|checkLicense|verifySignature|"
        r"checkSignature|checkAppIntegrity|validateIntegrity|"
        r"handleIntegrityResult|processIntegrityToken|verifyInstall|"
        r"validateToken|verifyDevice|"
        r"initializeLicenseCheck|scheduleRepeatedLicenseCheck|"
        r"reportSuccessfulLicenseCheck|populateInputDataForLicenseCheck|"
        r"checkLicenseInternal)\("
    )
    # Detect PairIP class presence in file – if found, stub ALL non-abstract methods
    _PAIRIP_CLASS_RE = re.compile(
        r"Lcom/pairip/licensecheck/(?:LicenseClient|LicenseActivity|"
        r"LicenseContentProvider|LicenseResponseHelper|RepeatedCheckMetadata);",
        re.IGNORECASE,
    )
    # Separate regex for onFailure – requires integrity parent class context
    _INTEGRITY_ONFAILURE_RE = re.compile(
        r"\.method\s+(?:(?:public|private|protected|static|final)\s+)*"
        r"onFailure\("
    )
    # Class-level context that qualifies onFailure as integrity-related
    _INTEGRITY_CLASS_CONTEXT_RE = re.compile(
        r"(?:IntegrityManager|SafetyNet|LicenseChecker|IntegrityToken|"
        r"LicenseValidator|checkIntegrity|onIntegrity|"
        r"pairip|licensecheck|LicenseClient|LicenseActivity|"
        r"initializeLicenseCheck|scheduleRepeatedLicenseCheck)",
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
    def find_all(self, needed: frozenset | None = None):
        """
        Scan smali files for API patterns.

        Parameters
        ----------
        needed : frozenset of category names to scan (iap, integrity, ads,
                 storageIO, serverIO).  Pass None to scan ALL (e.g. detect-only
                 mode).  Scanning only needed categories saves minutes on large
                 APKs – no point scanning 6 000 ads files when patching
                 integrity only.
        """
        log("head", "API Detection")
        t0 = time.time()
        scan_all = needed is None

        cat_pats: list[tuple] = []
        if scan_all or "iap"       in needed: cat_pats += self.IAP_PATTERNS
        if scan_all or "integrity" in needed: cat_pats += self.INTEGRITY_PATTERNS
        if scan_all or "storageIO" in needed: cat_pats += self.STORAGE_PATTERNS
        if scan_all or "serverIO"  in needed: cat_pats += self.SERVER_PATTERNS
        if scan_all or "ads"       in needed: cat_pats += self.ADS_PATTERNS

        res = self.scanner.scan(cat_pats, label="API pattern scan")

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

        if scan_all or "iap"       in (needed or set()):
            log("ok", f"IAP files       : {C.BD}{len(self._iap)}{C.RS}")
        if scan_all or "integrity" in (needed or set()):
            log("ok", f"Integrity files : {C.BD}{len(self._int)}{C.RS}")
        if scan_all or "ads"       in (needed or set()):
            log("ok", f"Ads files       : {C.BD}{len(self._ads)}{C.RS}")
        if scan_all or "storageIO" in (needed or set()):
            log("ok", f"Storage files   : {C.BD}{len(self._sto)}{C.RS}")
        if scan_all or "serverIO"  in (needed or set()):
            log("ok", f"Server-reply    : {C.BD}{len(self._srv)}{C.RS}")
        log("ok", f"Scan time       : {time.time()-t0:.1f}s")

    # ── IAP patching ──────────────────────────────────────────────────────────
    def patch_iap(self) -> int:
        if not self._iap:
            log("warn", "No IAP files – skip."); return 0
        # Write the fake IAP binder smali class into the tree FIRST.
        # _patch_iap_file will then inject calls to FakeIAP.getInstance()
        # in ServiceConnection files, so FakeIAP must exist before rebuild.
        self._write_fake_iap_smali()
        log("info", f"Patching IAP ({len(self._iap)} files)…")
        total = self._patch_parallel(self._iap, self._patch_iap_file, "iap")
        log("ok",  f"IAP: {C.G}{total}{C.RS} patches applied.")
        return total

    def _patch_iap_file(self, rel: str) -> int:
        """
        Patch IAP-related smali using SmaliAST for structural decisions:
          - Method boundaries from AST (not raw .method/.end method regex)
          - Return type from AST descriptor (no regex false positives)
          - BillingResponseCode inline patch still uses line-scan (single invoke)

        Regex is only used for PATTERN MATCHING (what the method does), not
        for structural parsing (where it is / what type it returns).
        """
        path = os.path.join(self.base, rel)
        cls  = parse_smali(path)
        if cls is None:
            return 0
        lines   = cls.source_lines
        patched = 0
        # Track line-index shifts caused by body insertions
        # (AST line numbers are valid at parse time; we work top-to-bottom
        #  so shift only accumulates forward)
        shift = 0

        for method in cls.methods:
            if method.is_abstract or method.is_native:
                continue
            s  = method.declaration   # method declaration line (AST-parsed)
            ms = method.line_start + shift
            me = method.line_end   + shift

            # Bounds-guard: shift arithmetic must never produce out-of-range indices
            if ms < 0 or me >= len(lines) or ms > me:
                continue

            # ── Google Pay: isReadyToPay → force true ────────────────────────
            if re.search(r"->isReadyToPay\(", s) and re.search(r"\)Z$", s):
                nb  = ["    const/4 v0, 0x1\n", "    return v0\n"]
                old_len = me - ms + 1
                lines   = _safe_replace_body(lines, ms, me, nb,
                                             locals_n=1, tag="iap:gpay-ready→true")
                shift  += (1 + 1 + 1 + len(nb) + 1) - old_len
                patched += 1
                _REPORT.add("iap", rel, ms, "gpay_ready_true")
                log("patch", f"GPay isReadyToPay→true  {rel}  L{ms}", indent=1)
                continue

            # ── Google Pay: loadPaymentData → stub void ────────────────────
            if re.search(r"->loadPaymentData\(", s) and re.search(r"\)V$", s):
                nb  = ["    return-void\n"]
                old_len = me - ms + 1
                lines   = _safe_replace_body(lines, ms, me, nb,
                                             locals_n=0, tag="iap:gpay-load-stub")
                shift  += (1 + 1 + 1 + len(nb) + 1) - old_len
                patched += 1
                _REPORT.add("iap", rel, ms, "gpay_load_stub")
                log("patch", f"GPay loadPaymentData stub  {rel}  L{ms}", indent=1)
                continue

            # ── Purchase method: replace body with fake-success stub ──────────
            if self._PURCHASE_RE.search(s):
                cb  = self._find_callback(lines, ms, me)
                # Use correct return type: most purchase methods are void,
                # but launchBillingFlow returns BillingResult (an object).
                # Using return-void in a non-void method causes Dalvik verifier
                # to reject the class at runtime.
                nb  = self._iap_success_body(cb, method)
                loc = 1  # .locals 1 (v0 used for const-string or null)
                old_len = me - ms + 1
                lines   = _safe_replace_body(lines, ms, me, nb,
                                             locals_n=loc, tag="iap:purchase-stub")
                new_len = 1 + 1 + 1 + len(nb) + 1
                shift  += new_len - old_len
                patched += 1
                _REPORT.add("iap", rel, ms, "purchase_method_stub")
                log("patch", f"IAP purchase  {rel}  L{ms}", indent=1)
                continue

            # ── launchBillingFlow → direct success callback ──────────────────
            # Replaces the Play Store dialog with an instant success:
            # Gets OK BillingResult from zzcj.zzf, then calls
            # PurchasesUpdatedListener.onPurchasesUpdated(OK, []) directly.
            # Path: BillingClientImpl.zzf (zzs) → zzs.zzb (listener)
            if (method.name == "launchBillingFlow"
                    and "BillingFlowParams" in (method.descriptor or "")
                    and "BillingResult" in (method.return_type or "")):
                if not (method.is_abstract or method.is_native):
                    # Return pre-built OK BillingResult (zzcj.zzf has code=0).
                    # Also call onPurchasesUpdated(OK, emptyList) so the app's
                    # purchase listener fires immediately without Play Store dialog.
                    # Build JSON string for fake Purchase - escape " as \" for smali
                    _pj = ('{"orderId":"UG.bypass","packageName":"com.ug",'
                           '"productIds":["bypass"],"purchaseState":0,'
                           '"purchaseToken":"ug_token_bypass","acknowledged":true}')
                    _pj_s = _pj.replace('"', '\\\"'  )   # " → \" in smali
                    nb = [
                        "    sget-object v0, Lcom/android/billingclient/api/zzcj;"
                        "->zzf:Lcom/android/billingclient/api/BillingResult;\n",
                        "    iget-object v1, p0, Lcom/android/billingclient/api/BillingClientImpl;"
                        "->zzf:Lcom/android/billingclient/api/zzs;\n",
                        "    if-eqz v1, :ug_ret\n",
                        "    iget-object v1, v1, Lcom/android/billingclient/api/zzs;"
                        "->zzb:Lcom/android/billingclient/api/PurchasesUpdatedListener;\n",
                        "    if-eqz v1, :ug_ret\n",
                        "    new-instance v2, Ljava/util/ArrayList;\n",
                        "    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V\n",
                        "    new-instance v3, Lcom/android/billingclient/api/Purchase;\n",
                        f'    const-string v4, "{_pj_s}"\n',
                        '    const-string v5, ""\n',
                        "    invoke-direct {v3, v4, v5}, Lcom/android/billingclient/api/Purchase;"
                        "-><init>(Ljava/lang/String;Ljava/lang/String;)V\n",
                        "    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z\n",
                        "    invoke-interface {v1, v0, v2}, Lcom/android/billingclient/api/"
                        "PurchasesUpdatedListener;->onPurchasesUpdated("
                        "Lcom/android/billingclient/api/BillingResult;Ljava/util/List;)V\n",
                        "    :ug_ret\n",
                        "    return-object v0\n",
                    ]
                    old_len = me - ms + 1
                    lines   = _safe_replace_body(lines, ms, me, nb, locals_n=6,
                                                 tag="iap:launchBillingFlow-direct")
                    new_len = 1 + 1 + 1 + len(nb) + 1
                    shift  += new_len - old_len
                    patched += 1
                    _REPORT.add("iap", rel, ms, "launch_billing_flow_direct")
                    log("patch", f"launchBillingFlow→direct  {rel}  L{ms}", indent=1)
                    continue

            # ── BillingResult.getResponseCode()I → return 0 (OK) ─────────────
            # Only stub getResponseCode() when the class IS a billing class.
            # Class-name guard prevents patching HTTP/WebRequest response codes
            # which would break all network communication in the app.
            if (self._BILLING_RESULT_GETTER_RE.search(s)
                    and self._BILLING_CLASS_RE.search(cls.class_name + " " + cls.super_name)):
                if not (method.is_abstract or method.is_native):
                    nb  = ["    const/4 v0, 0x0\n", "    return v0\n"]
                    old_len = me - ms + 1
                    lines   = _safe_replace_body(lines, ms, me, nb, locals_n=1,
                                                 tag="iap:getResponseCode=OK")
                    new_len = 1 + 1 + 1 + len(nb) + 1
                    shift  += new_len - old_len
                    patched += 1
                    _REPORT.add("iap", rel, ms, "billing_response_code_ok")
                    log("patch",
                        f"getResponseCode→0(OK)  {rel}  L{ms}",
                        indent=1)
                    continue

            # ── queryPurchasesAsync stub → onQueryPurchasesResponse(OK, []) ─────
            # Called on app startup to restore owned purchases.
            # Stub to return OK + empty list so the app doesn't hang.
            # NOTE: empty list = no existing purchases shown at startup.
            # Real unlocking happens via isPremium() bool-gate patches.
            if method.name == "queryPurchasesAsync":
                if not (method.is_abstract or method.is_native):
                    # Method sig: queryPurchasesAsync(QueryPurchasesParams, PurchasesResponseListener)V
                    # p2 = PurchasesResponseListener
                    if method.descriptor and "PurchasesResponseListener" in method.descriptor:
                        nb = [
                            "    sget-object v0, Lcom/android/billingclient/api/zzcj;"
                            "->zzf:Lcom/android/billingclient/api/BillingResult;\n",
                            "    new-instance v1, Ljava/util/ArrayList;\n",
                            "    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V\n",
                            "    invoke-interface {p2, v0, v1}, Lcom/android/billingclient/api/"
                            "PurchasesResponseListener;->onQueryPurchasesResponse("
                            "Lcom/android/billingclient/api/BillingResult;Ljava/util/List;)V\n",
                            "    return-void\n",
                        ]
                        old_len = me - ms + 1
                        lines   = _safe_replace_body(lines, ms, me, nb, locals_n=2,
                                                     tag="iap:queryPurchasesAsync-ok")
                        new_len = 1 + 1 + 1 + len(nb) + 1
                        shift  += new_len - old_len
                        patched += 1
                        _REPORT.add("iap", rel, ms, "query_purchases_ok")
                        log("patch", f"queryPurchasesAsync→OK  {rel}  L{ms}", indent=1)
                        continue

            # ── isAcknowledged()Z → return true ──────────────────────────────
            # Purchase.isAcknowledged() must return true or Play considers the
            # purchase pending and shows it as unconfirmed.
            if re.search(r"\.method\s+[^(]*isAcknowledged\(\)Z", s):
                if not (method.is_abstract or method.is_native):
                    nb = ["    const/4 v0, 0x1\n", "    return v0\n"]
                    old_len = me - ms + 1
                    lines   = _safe_replace_body(lines, ms, me, nb, locals_n=1,
                                                 tag="iap:isAcknowledged→true")
                    new_len = 1 + 1 + 1 + len(nb) + 1
                    shift  += new_len - old_len
                    patched += 1
                    _REPORT.add("iap", rel, ms, "is_acknowledged_true")
                    log("patch", f"isAcknowledged→true  {rel}  L{ms}", indent=1)
                    continue

            # ── IInAppBillingService.Stub.asInterface() → inject FakeIAP ─────────
            # When the billing library's ServiceConnection.onServiceConnected()
            # receives the IBinder from Play Store, it calls asInterface(binder)
            # to wrap it. We replace the binder with FakeIAP.getInstance()
            # BEFORE asInterface() is called. This redirects ALL billing AIDL
            # calls through our fake service instead of Play Store.
            #
            # Pattern: invoke-static {regN}, Lcom/android/vending/billing/
            #              IInAppBillingService$Stub;->asInterface(...)
            for instr in method.instrs:
                if ("IInAppBillingService" in instr.raw and
                        "asInterface" in instr.raw and
                        "invoke-static" in instr.raw):
                    ln = instr.line_no + shift
                    if 0 <= ln < len(lines):
                        # Extract the register passed to asInterface
                        m2 = re.search(r"invoke-static\s+\{([vp]\d+)\}", lines[ln])
                        if m2:
                            reg = m2.group(1)
                            try:
                                rn = int(reg[1:])
                                if rn <= 15:
                                    # Replace the binder with our fake one
                                    inject = (
                                        f"    invoke-static {{}}, Lcom/ug/iap/FakeIAP;"
                                        f"->getInstance()Lcom/ug/iap/FakeIAP;"
                                        f"  # UNGUARD: fake-iap-binder\n"
                                        f"    move-result-object {reg}\n"
                                    )
                                    lines.insert(ln, inject)
                                    shift += 1
                                    patched += 1
                                    _REPORT.add("iap", rel, ln, "fake_iap_binder")
                                    log("patch",
                                        f"FakeIAP binder injected  {rel}  L{ln}",
                                        indent=1)
                            except (ValueError, IndexError):
                                pass
                    break

            # ── Boolean gate: isPremium()Z → return true ──────────────────────
            if self._BOOL_GATE_RE.search(s):
                nb  = ["    const/4 v0, 0x1\n", "    return v0\n"]
                old_len = me - ms + 1
                lines   = _safe_replace_body(lines, ms, me, nb,
                                             locals_n=1, tag="iap:bool-gate→true")
                new_len = 1 + 1 + 1 + len(nb) + 1
                shift  += new_len - old_len
                patched += 1
                _REPORT.add("iap", rel, ms, "bool_gate_true")
                log("patch", f"IAP bool gate  {rel}  L{ms}", indent=1)
                continue

            # ── Google Pay: isReadyToPay / canMakePayment → true ─────────────
            # These are called as Task<Boolean> – the boolean result matters
            # The BOOL_GATE_RE already handles methods NAMED isReadyToPay()Z
            # This handles the inline Task result extraction pattern:
            #   invoke-virtual {vX}, Lcom/google/android/gms/tasks/Task;->getResult()
            for instr in method.instrs:
                if ("getResult()Ljava/lang/Object;" in instr.raw
                        and "Task;" in instr.raw
                        and "invoke-virtual" in instr.raw):
                    ln = instr.line_no + shift
                    if 0 <= ln < len(lines):
                        # Look ahead for Boolean.booleanValue() unbox
                        for k in range(ln+1, min(ln+8, len(lines))):
                            if ("Boolean;->booleanValue()Z" in lines[k]
                                    and "invoke-virtual" in lines[k]):
                                j = _next_move_result_idx(lines, k)
                                if j and 0 <= j < len(lines):
                                    m2 = re.match(r"([ 	]+)(move-result)\s+([vp]\d+)", lines[j])
                                    if m2:
                                        reg = m2.group(3)
                                        try:
                                            if int(reg[1:]) <= 15:
                                                lines.insert(j+1, f"    const/4 {reg}, 0x1  # UNGUARD: GPay ready=true\n")
                                                shift += 1
                                                patched += 1
                                                _REPORT.add("iap", rel, j, "gpay_ready_true")
                                        except (ValueError, IndexError):
                                            pass
                                break
                    break

            # ── Unity WebViewStoreEventListener gate patch ────────────────────
            # onPurchaseUpdated and onBillingSetupFinished both have this gate:
            #   getResponseCode() → compare to OK → if-ne → error path
            # We patch the if-ne to goto the success label directly.
            # This makes Unity's WebView always receive the success event,
            # bypassing the response code check entirely.
            if method.name in ("onPurchaseUpdated", "onBillingSetupFinished",
                               "onPurchaseResponse"):
                # Find the if-ne that gates on BillingResultResponseCode.OK
                for instr in method.instrs:
                    if instr.opcode not in ("if-ne", "if-eq"):
                        continue
                    ln = instr.line_no + shift
                    if 0 <= ln < len(lines):
                        line = lines[ln]
                        # Pattern: if-ne vX, vY, :cond_N
                        # We want the one after a BillingResultResponseCode compare
                        # Look back a few lines for the sget-object BillingResultResponseCode;->OK
                        lookback = "\n".join(lines[max(0, ln-5):ln])
                        if ("BillingResultResponseCode" in lookback or
                                "PURCHASES_UPDATED" in lookback or
                                "INITIALIZATION_REQUEST" in lookback):
                            m2 = re.match(
                                r"([ \t]+)if-(?:ne|eq)\s+\w+,\s+\w+,\s+(:cond_\w+)",
                                line)
                            if m2:
                                indent = m2.group(1)
                                error_label = m2.group(2)
                                # Replace if-ne (jump to error) with nop
                                # → execution falls through to success path
                                lines[ln] = f"{indent}nop  # UNGUARD: unity-gate-bypass\n"
                                shift += 0  # same line count
                                patched += 1
                                _REPORT.add("iap", rel, ln, "unity_gate_bypass")
                                log("patch",
                                    f"Unity gate bypass  {rel}  L{ln}  ({method.name})",
                                    indent=1)
                                break

            # ── getPurchaseState() → 1 (PURCHASED) inline ────────────────────
            # Intercept the result of Purchase.getPurchaseState() and force it
            # to PURCHASED (1) so all ownership checks pass.
            for instr in method.instrs:
                ln = instr.line_no + shift
                if 0 <= ln < len(lines):
                    if ("->getPurchaseState()I" in instr.raw
                            and "invoke-virtual" in instr.raw):
                        j = _next_move_result_idx(lines, ln)
                        if j is not None:
                            m2 = re.match(r"([ \t]+)(move-result)\s+([vp]\d+)", lines[j])
                            if m2:
                                reg = m2.group(3)
                                try:
                                    if int(reg[1:]) <= 15:
                                        lines.insert(j + 1,
                                            f"    const/4 {reg}, 0x1"
                                            f"  # UNGUARD: purchaseState=PURCHASED\n")
                                        shift += 1
                                        patched += 1
                                        _REPORT.add("iap", rel, j, "purchase_state_purchased")
                                        log("patch",
                                            f"getPurchaseState→PURCHASED  {rel}  L{j}",
                                            indent=1)
                                except (ValueError, IndexError):
                                    pass
                        break  # one patch per method for getPurchaseState

            # ── onPurchasesUpdated: force OK response ────────────────────────
            # Called after launchBillingFlow completes. Force responseCode=0
            # so the app processes the (fake) purchases list.
            if method.name == "onPurchasesUpdated":
                for instr in method.instrs:
                    ln = instr.line_no + shift
                    if 0 <= ln < len(lines):
                        if ("BillingResult;->getResponseCode()I" in instr.raw
                                and "invoke-virtual" in instr.raw):
                            j = _next_move_result_idx(lines, ln)
                            if j is not None:
                                m2 = re.match(r"([ \t]+)(move-result)\s+([vp]\d+)", lines[j])
                                if m2:
                                    reg = m2.group(3)
                                    try:
                                        if int(reg[1:]) <= 15:
                                            lines.insert(j + 1,
                                                f"    const/4 {reg}, 0x0"
                                                f"  # UNGUARD: purchasesUpdated=OK\n")
                                            shift += 1
                                            patched += 1
                                            _REPORT.add("iap", rel, j,
                                                        "purchases_updated_ok")
                                    except (ValueError, IndexError):
                                        pass
                            break

            # ── BillingResponseCode → 0 (OK) inline ──────────────────────────
            # Line-scan within this method's current (shifted) body
            for instr in method.instrs:
                ln = instr.line_no + shift
                # Bounds-guard: shift may move ln outside valid range
                if ln < 0 or ln >= len(lines):
                    continue
                if ("BillingResult;->getResponseCode()I" in instr.raw
                        and "invoke-virtual" in instr.raw):
                    j = _next_move_result_idx(lines, ln)
                    if j is not None:
                        m2 = re.match(r"([ \t]+)(move-result)\s+([vp]\d+)", lines[j])
                        if m2:
                            reg = m2.group(3)
                            # Skip if register > v15 (const/4 is 4-bit only)
                            try:
                                if int(reg[1:]) > 15:
                                    break
                            except (ValueError, IndexError):
                                pass
                            inject = (f"    const/4 {reg}, 0x0"
                                      f"  # UNGUARD: BillingResponseCode=OK\n")
                            lines.insert(j + 1, inject)
                            shift += 1
                            me_safe = min(me + shift + 1, len(lines))
                            _propagate_register_alias(
                                lines, j + 1, reg, "0x0", me_safe)
                            patched += 1
                            _REPORT.add("iap", rel, j, "billing_code_ok")
                    break

        if patched:
            _atomic_write(path, lines)
            _verify_patch(path, expected_min=patched)
        return patched

    @staticmethod
    def _iap_success_body(cb, method: "SmaliMethod | None" = None) -> list[str]:
        """
        Build the stub body for a purchase method.

        Return type logic:
          V  → return-void          (most purchase flow launchers)
          L… → return-object v0     (launchBillingFlow → BillingResult, etc.)
          Z  → const/4 v0, 0x1 + return v0
          default → return-void (safe fallback)

        The purchase token JSON string is embedded as a const-string with all
        inner double-quotes escaped as \" so apktool's smali assembler does not
        misparse the closing delimiter.
        """
        raw_json  = '{"productId":"bypass","purchaseToken":"unguard","purchaseState":1}'
        smali_str = raw_json.replace('"'  , '\\\"'  )   # " → \"  in smali output

        rt = "V"
        if method is not None:
            rt = method.return_type or "V"

        if rt == "Z":
            # boolean return (e.g. isReadyToPay)
            return ["    const/4 v0, 0x1\n", "    return v0\n"]

        if rt == "V":
            # void – standard purchase flow: embed JSON token for analytics,
            # then call the success callback if found, then return void.
            body = [f'    const-string v0, "{smali_str}"\n']
            if cb:
                body.append(f"    invoke-static {{v0}}, {cb[0]}->{cb[1]}(Ljava/lang/String;)V\n")
            body.append("    return-void\n")
            return body

        # Non-void, non-boolean: object/int return (launchBillingFlow → BillingResult)
        # Return null – the caller must handle null BillingResult gracefully.
        # For BillingResult specifically this is fine because the next call to
        # getResponseCode() on null will be caught by our BillingResponseCode=0 patch.
        body = [f'    const-string v0, "{smali_str}"\n', "    const/4 v0, 0x0\n",
                "    return-object v0\n"]
        return body

    @staticmethod
    def _find_callback(lines, start, end):
        """
        Search for a static void callback that accepts a single String argument.
        Used to optionally call success callbacks in purchase stubs.
        IMPORTANT: the callback invocation is only emitted when the signature
        matches exactly (L…;→method(Ljava/lang/String;)V). Any other signature
        would crash at runtime, so we deliberately skip non-matching callbacks.
        """
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
        """
        SmaliAST-driven integrity patching:
         - PairIP detection uses class_name + super_name (no false-positive from
           string constants or annotation values containing the class name)
         - Return type comes from method.return_type (descriptor), not regex
         - Method boundaries are exact (no .end method misalignment)
         - onFailure scoping uses implements[] and super_name, not line regex
        """
        path = os.path.join(self.base, rel)
        cls  = parse_smali(path)
        if cls is None:
            return 0
        lines   = cls.source_lines
        patched = 0
        shift   = 0

        # AST-level class context checks (reliable: never matches string literals)
        is_pairip_file = bool(self._PAIRIP_CLASS_RE.search(
            " ".join([cls.class_name, cls.super_name] + cls.implements)))
        is_integrity_class = (
            is_pairip_file or
            bool(self._INTEGRITY_CLASS_CONTEXT_RE.search(
                " ".join([cls.class_name, cls.super_name] + cls.implements)))
        )
        # Also check if any method DECLARATION (not body) carries integrity names
        # (catches classes that delegate to integrity APIs without inheriting)
        if not is_integrity_class:
            is_integrity_class = any(
                self._INTEGRITY_CLASS_CONTEXT_RE.search(m.declaration)
                for m in cls.methods
            )
        for method in cls.methods:
            if method.is_abstract or method.is_native:
                continue
            ms = method.line_start + shift
            me = method.line_end   + shift
            # Bounds-guard
            if ms < 0 or me >= len(lines) or ms > me:
                continue
            old_len = me - ms + 1

            # ── PairIP whole-class: stub every method ─────────────────────────
            if is_pairip_file:
                nb, loc = self._stub_for_return_type_ast(method)
                lines    = _safe_replace_body(lines, ms, me, nb, loc,
                                              tag="integrity:pairip-stub")
                new_len  = 1 + 1 + 1 + len(nb) + 1
                shift   += new_len - old_len
                patched += 1
                _REPORT.add("integrity", rel, ms, "pairip_stub")
                log("patch", f"PairIP stub  {rel}  L{ms}", indent=1)
                continue

            # ── Named integrity method ─────────────────────────────────────────
            is_on_failure = (method.name == "onFailure" and is_integrity_class)
            if (self._INTEGRITY_RE.search(method.declaration) or is_on_failure):
                nb, loc = self._stub_for_return_type_ast(method)
                lines    = _safe_replace_body(lines, ms, me, nb, loc,
                                              tag="integrity:stub")
                new_len  = 1 + 1 + 1 + len(nb) + 1
                shift   += new_len - old_len
                patched += 1
                _REPORT.add("integrity", rel, ms, "integrity_stub")
                log("patch", f"Integrity  {rel}  L{ms}", indent=1)
                continue

            # ── Inline nop: sig/installer checks inside ANY method ────────────
            for instr in method.instrs:
                if ("->signatures" in instr.raw
                        or "->getInstallerPackageName" in instr.raw
                        or "->getInstallerPackageNameCompat" in instr.raw):
                    ln = instr.line_no + shift
                    lines[ln] = f"    # UNGUARD-NOP: {instr.raw}\n"
                    _REPORT.add("integrity", rel, ln, "sig_check_nop")
                    patched += 1

        if patched:
            _atomic_write(path, lines)
            _verify_patch(path, expected_min=patched)
        return patched

    @staticmethod
    def _stub_for_return_type(method_decl: str) -> tuple[list[str], int]:
        """Return (body_lines, locals_n) stub matching the method return type.
        Used when we only have the declaration string (legacy/fallback path)."""
        m = re.search(r"\)([VZBSCFIJD]|\[+[VZBSCFIJD]|\[+L[^;]+;|L[^;]+;)\s*$",
                      method_decl)
        rt = m.group(1) if m else "V"
        if rt == "Z":
            return ["    const/4 v0, 0x1\n", "    return v0\n"], 1
        elif rt == "V":
            return ["    return-void\n"], 0
        elif rt in ("I", "B", "S", "C", "F"):
            return ["    const/4 v0, 0x1\n", "    return v0\n"], 1
        elif rt in ("J", "D"):
            return ["    const-wide/16 v0, 0x0\n", "    return-wide v0\n"], 2
        else:
            return ["    const/4 v0, 0x0\n", "    return-object v0\n"], 1

    @staticmethod
    def _stub_for_return_type_ast(method: SmaliMethod) -> tuple[list[str], int]:
        """Return (body_lines, locals_n) using the AST-parsed return type.
        More reliable than regex on the declaration string: the AST descriptor
        was parsed from the structured JVM type system, not by matching text."""
        rt = method.return_type
        if not rt:
            rt = "V"
        if rt == "Z":
            return ["    const/4 v0, 0x1\n", "    return v0\n"], 1
        elif rt == "V":
            return ["    return-void\n"], 0
        elif rt in ("I", "B", "S", "C", "F"):
            return ["    const/4 v0, 0x1\n", "    return v0\n"], 1
        elif rt in ("J", "D"):
            return ["    const-wide/16 v0, 0x0\n", "    return-wide v0\n"], 2
        else:  # L…; or [… (object / array) → null
            return ["    const/4 v0, 0x0\n", "    return-object v0\n"], 1

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
                if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                    j = _next_move_result_idx(lines, i)
                    end = _method_end(lines, i)
                    inject = f"    const/4 {reg}, 0x1  # UNGUARD: Room DAO prem=1\n"
                    lines.insert(j + 1, inject)
                    if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                    _REPORT.add("storageIO", rel, j, "room_dao_one")
                    n_tot += 1; i = j + 2; continue

            # MMKV.decodeBool near premium key → force true
            if ("MMKV;->decodeBool(" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=4):
                    reg = _next_move_result(lines, i)
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        inject = f"    const/4 {reg}, 0x1  # UNGUARD: MMKV.decodeBool=true\n"
                        lines.insert(j + 1, inject)
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("storageIO", rel, j, "mmkv_bool_true")
                        n_tot += 1; i = j + 2; continue

            # MMKV.decodeInt near premium key → force 1
            if ("MMKV;->decodeInt(" in s and "invoke-" in s):
                if self._near_prem_key(lines, i, lookback=4):
                    reg = _next_move_result(lines, i)
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        inject = f"    const/4 {reg}, 0x1  # UNGUARD: MMKV.decodeInt=1\n"
                        lines.insert(j + 1, inject)
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("storageIO", rel, j, "mmkv_int_one")
                        n_tot += 1; i = j + 2; continue

            i += 1

        if n_tot:
            _atomic_write(path, lines)
            log("patch", f"Storage  {rel}  ({n_tot}x)", indent=1)
            _verify_patch(path, expected_min=n_tot)
        return n_tot

    def _write_fake_iap_smali(self) -> None:
        """Write FakeIAP.smali into the decompiled smali tree.

        Only injected when files calling IInAppBillingService.Stub.asInterface()
        are found (old AIDL-based billing, pre-v4). Modern apps using gRPC
        billing (v4+) don't use asInterface() so this is skipped.

        When product IDs can be extracted from the smali, they are embedded in
        the fake purchase JSON returned by getBuyIntent (transaction code 3).
        This means the app's own product IDs appear in the fake purchase receipt,
        making the PoC realistic: the app's purchase callback receives a purchase
        object whose getProducts() list matches what the developer registered.
        """
        # Check if any IAP file contains AIDL asInterface() call
        has_aidl = False
        for rel in self._iap:
            path = os.path.join(self.base, rel)
            try:
                content = open(path, encoding="utf-8", errors="ignore").read()
                if "IInAppBillingService" in content and "asInterface" in content:
                    has_aidl = True
                    break
            except Exception:
                pass
        if not has_aidl:
            return

        # Extract product IDs from the app's own smali
        product_ids = self.extract_product_ids()
        # Use first found ID, or generic fallback
        product_id = sorted(product_ids)[0] if product_ids else "bypass"
        if product_ids:
            log("ok",
                f"FakeIAP: using app product IDs: {sorted(product_ids)[:5]}",
                indent=1)

        # Build purchase JSON with real product ID - escape " as \" for smali
        raw_json = (
            f'{{"orderId":"UG.{product_id}","packageName":"com.ug",'
            f'"productIds":["{product_id}"],"purchaseState":0,'
            f'"purchaseToken":"ug_token_{product_id}","acknowledged":true}}'
        )
        smali_json = raw_json.replace('"'  , '\\"'  )

        # Stamp product ID into FakeIAP smali template
        smali_content = _SMALI_FAKE_IAP.replace(
            '__UG_PRODUCT_ID__', product_id).replace(
            '__UG_PURCHASE_JSON__', smali_json)

        pkg_dir = Path(self.base) / "smali" / "com" / "ug" / "iap"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        dest = pkg_dir / "FakeIAP.smali"
        if not dest.is_file():
            dest.write_text(smali_content, encoding="utf-8")
            log("ok",
                f"FakeIAP.smali injected (product_id={product_id!r})",
                indent=1)

    # ── IAP product ID extractor ─────────────────────────────────────────────
    _IAP_CALL_RE = re.compile(
        r"getBuyIntent|querySkuDetails|queryPurchasesAsync|"
        r"queryProductDetailsAsync|addProductId|setSkusList|setProductId",
        re.IGNORECASE)
    _SKU_STR_RE  = re.compile(r'const-string\s+\w+,\s+"([a-z][a-z0-9._]{2,99})"')
    _SKU_NOISE_RE = re.compile(
        r"^(?:android|google|firebase|unity|applovin|facebook|"
        r"ironSource|chartboost|vungle|token|session|provider|package|"
        r"protocol|process|profile|signal|mediation|waterfall|bundle_|"
        r"native_|start_|end_|load_|show_|init_)", re.IGNORECASE)

    def extract_product_ids(self) -> set[str]:
        """
        Scan IAP-tagged smali files for hardcoded product ID strings.
        Product IDs appear as const-strings near querySkuDetails /
        getBuyIntent / queryProductDetailsAsync calls.
        Returns a set of candidate product ID strings.
        """
        found: set[str] = set()
        for rel in self._iap:
            path = os.path.join(self.base, rel)
            try:
                text = open(path, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines):
                window = "\n".join(lines[max(0, i-5):min(len(lines), i+12)])
                if not self._IAP_CALL_RE.search(window):
                    continue
                for m in self._SKU_STR_RE.finditer(window):
                    val = m.group(1)
                    if self._SKU_NOISE_RE.search(val):
                        continue
                    # Must look like a product ID: has _ or . and no spaces
                    if ("_" in val or "." in val) and len(val) >= 4:
                        found.add(val)
        return found

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
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                        j = _next_move_result_idx(lines, i)
                        end = _method_end(lines, i)
                        lines.insert(j + 1,
                            f"    const/4 {reg}, 0x1  # UNGUARD: JSON int=1\n")
                        if end: _propagate_register_alias(lines, j+1, reg, "0x1", end+1)
                        _REPORT.add("serverIO", rel, j, "json_int_one")
                        n_tot += 1; i = j + 2; continue

            # JSONObject.getLong/optLong near status key → force 1L
            # getLong() returns J (long, 64-bit) → move-result-wide → const-wide
            if ("JSONObject;->getLong(" in s or "JSONObject;->optLong(" in s):
                if self._near_status_key(lines, i, lookback=5):
                    # move-result-wide uses two consecutive registers
                    j = _next_move_result_idx(lines, i)
                    if j is not None:
                        mw = re.match(r"[ \t]*move-result-wide\s+([vp]\d+)", lines[j])
                        if mw:
                            reg = mw.group(1)
                            try:
                                rn = int(reg[1:])
                                if rn <= 14:  # need reg and reg+1 both ≤ 15
                                    lines.insert(j + 1,
                                        f"    const-wide/16 {reg}, 0x1"
                                        f"  # UNGUARD: JSON long=1\n")
                                    _REPORT.add("serverIO", rel, j, "json_long_one")
                                    n_tot += 1; i = j + 2; continue
                            except (ValueError, IndexError):
                                pass

            # JSONObject.getBoolean/optBoolean near status/success key → force true
            if ("JSONObject;->getBoolean(" in s or "JSONObject;->optBoolean(" in s):
                if self._near_status_key(lines, i, lookback=5):
                    reg = _next_move_result(lines, i)
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                    j = _next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    _REPORT.add("serverIO", rel, j, "http_code_200")
                    n_tot += 1; i = j + 2; continue

            # Retrofit2 / OkHttp .isSuccessful() → true
            if (("retrofit2/Response;->isSuccessful()" in s or
                 "okhttp3/Response;->isSuccessful()" in s) and "invoke-virtual" in s):
                reg = _next_move_result(lines, i)
                if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
                    j = _next_move_result_idx(lines, i)
                    lines.insert(j + 1,
                        f"    const/16 {reg}, 0xc8  # UNGUARD: HTTP=200\n")
                    _REPORT.add("serverIO", rel, j, "http_url_200")
                    n_tot += 1; i = j + 2; continue

            # JSONArray.length() near status context → force 1 (non-empty)
            if ("JSONArray;->length()" in s and "invoke-virtual" in s):
                if self._near_status_key(lines, i, lookback=8):
                    reg = _next_move_result(lines, i)
                    if reg and not (reg.startswith("v") and int(reg[1:]) > 15):
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
                i += 1 + 1 + 1 + len(nb); continue

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
                i += 1 + 1 + 1 + len(nb); continue

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
                i += 1 + 1 + 1 + len(nb); continue

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

        # Quick pre-filter: if none of our heavyweight patterns are present
        # anywhere in the cache, skip the full per-file scan entirely.
        _PREFILTER = re.compile(
            r"xor-int|AES|DES|javax/crypto|ClassLoader|dalvik/system|"
            r"goto/|:goto_|StringBuilder|Method\.invoke", re.IGNORECASE)
        corpus_sample = "".join(
            text[:2000] for _, text in list(self.cache.items())[:200])
        if not _PREFILTER.search(corpus_sample):
            log("info",
                "Custom obf pre-filter: no obfuscation signals in sample – "
                "skipping full custom scan.", indent=1)
            return {}

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
        ("assets/UnrealGame",                  "unreal"),
        ("assets/Paks",                        "unreal"),
        ("assemblies/Xamarin",                 "xamarin"),
        ("assemblies/mscorlib.dll",            "xamarin"),
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
        "pairip":     [r"com/pairip/licensecheck",r"LicenseClient",
                       r"initializeLicenseCheck"],
        "kiwi":       [r"com/kiwi/security"],
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
        "pairip":35,"kiwi":20,
    }

    def __init__(self, cache: SmaliCache, target_apk: str, workers: int = MAX_WORKERS):
        self.cache   = cache
        self.target  = target_apk
        self.workers = workers
        self.found: dict[str, list] = defaultdict(list)
        self.score   = 0

    def detect(self) -> dict:
        log("head", "Commercial Obfuscation Detection")
        # Phase 1: instant ZIP scan (checks lib names, folder names)
        self._check_zip()
        # If ZIP scan already found strong commercial obfuscator signals,
        # skip the expensive per-file smali scan entirely.
        zip_score = sum(self.SCORE_MAP.get(k, 10) for k in self.found)
        if zip_score >= 35:
            log("info",
                f"ZIP scan score={zip_score} – skipping full smali scan "
                f"(obfuscator already confirmed).", indent=1)
            for k in self.found: self.score += self.SCORE_MAP.get(k, 10)
            self.score = min(self.score, 100)
            if self.found:
                for tool, ev in self.found.items():
                    log("detect", f"{C.BD}{tool.upper()}{C.RS}  ({len(ev)} hit(s))", indent=1)
                log("warn", f"Commercial obfuscation score: {C.BD}{self.score}/100{C.RS}")
            return dict(self.found)
        # Phase 2: full smali scan (only if ZIP gave no strong signal)
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
                    nl = name.lower()
                    if re.search(r"libdexguard", nl):
                        self.found["dexguard"].append(name)
                    if re.search(r"libprotect|libjiagu|libshell|libsecexe", nl):
                        self.found["packer_native"].append(name)
                    if re.search(r"com/pairip|pairip", nl):
                        self.found["pairip"].append(name)
                    if re.search(r"com/guardsquare|com/saikoa", nl):
                        self.found["dexguard"].append(name)
                    if re.search(r"com/arxan|com/irdeto|com/verimatrix", nl):
                        self.found["arxan"].append(name)
                    if re.search(r"com/inka/android/appsealing", nl):
                        self.found["appsealing"].append(name)
                    if re.search(r"com/qihoo/jiagu|com/360safe", nl):
                        self.found["jiagu360"].append(name)
                    if re.search(r"com/secshell|com/bangcle", nl):
                        self.found["bangcle"].append(name)
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
        # Split APKs extracted alongside the base (re-signed after build)
        self.split_apks  : list[str] = []
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

    def _merge_splits_into_base(self, base_apk: str, split_apks: list) -> str | None:
        """Merge split APKs into the base APK.

        Copies lib/, assets/, and DEX files (classes*.dex) from each split
        into the base. DEX files from splits are renamed to avoid collisions:
        classes.dex from a split becomes classesN.dex where N continues from
        the highest existing index in the base.
        Returns path to merged signed APK, or None on failure.
        """
        import zipfile as _zf, shutil as _sh, re as _re
        if not base_apk or not os.path.isfile(base_apk):
            return None
        try:
            out = base_apk.replace(".apk", "_merged.apk")
            _sh.copy2(base_apk, out)
            merged_entries = 0

            with _zf.ZipFile(out, "a", compression=_zf.ZIP_DEFLATED) as zout:
                existing = set(zout.namelist())

                # Find highest existing classes index in base
                dex_indices = {0}  # classes.dex = index 0
                for name in existing:
                    m = _re.match(r"classes(\d+)\.dex", name)
                    if m:
                        dex_indices.add(int(m.group(1)))
                next_dex = max(dex_indices) + 1

                for split in split_apks:
                    if not os.path.isfile(split):
                        continue
                    with _zf.ZipFile(split, "r") as zsplit:
                        for entry in zsplit.infolist():
                            name = entry.filename

                            # lib/ and assets/ — copy as-is
                            if name.startswith("lib/") or name.startswith("assets/"):
                                if name not in existing:
                                    zout.writestr(entry, zsplit.read(name))
                                    existing.add(name)
                                    merged_entries += 1

                            # DEX files — rename to avoid collision
                            elif _re.match(r"classes\d*\.dex$", name):
                                new_name = f"classes{next_dex}.dex"
                                data = zsplit.read(name)
                                info = _zf.ZipInfo(new_name)
                                info.compress_type = _zf.ZIP_DEFLATED
                                zout.writestr(info, data)
                                existing.add(new_name)
                                next_dex += 1
                                merged_entries += 1
                                log("info", f"  Split DEX: {name} → {new_name}", indent=1)

            if merged_entries == 0:
                try: os.unlink(out)
                except: pass
                log("info", "Splits had no mergeable entries.", indent=1)
                return None

            log("ok", f"Merged {merged_entries} entries from {len(split_apks)} split(s).", indent=1)
            signed_out = self.sign(out, "merged")
            if signed_out and os.path.isfile(signed_out):
                try: os.unlink(out)
                except: pass
                return signed_out
            return out
        except Exception as e:
            log("warn", f"Merge splits failed: {e}")
            return None

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
        """
        Convert .aab → patchable base.apk using bundletool.

        Strategy (in order):
          1. bundletool --mode=universal → universal.apk (recommended, patches all arches)
          2. bundletool --mode=default  → per-device splits (extracts base + arch splits)
          3. Fallback: pass .aab directly to apktool (often fails for complex bundles)
        """
        apks_out = os.path.join(self.work_dir, "from_aab.apks")
        if not os.path.isfile(BUNDLETOOL):
            log("warn", f"  bundletool.jar not found at '{BUNDLETOOL}'. "
                "Download from https://github.com/google/bundletool/releases "
                "and set BUNDLETOOL env var or --bundletool flag.")
            log("warn", "  Attempting apktool directly on AAB (may fail).")
            return

        java_opts = os.environ.get("JAVA_OPTS", "").split()

        # Try universal mode first (single APK, easiest to patch)
        for mode in ("universal", "default"):
            try:
                log("info", f"  bundletool --mode={mode}…")
                cmd = (["java"] + java_opts + ["-jar", BUNDLETOOL, "build-apks",
                       f"--bundle={self.target}",
                       f"--output={apks_out}",
                       f"--mode={mode}", "--overwrite"])
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if r.returncode == 0 and os.path.isfile(apks_out):
                    log("ok", f"  bundletool ({mode}) OK")
                    base = self._extract_from_apks_zip(apks_out)
                    if base:
                        self.target = base
                        log("ok", f"  Base APK: {base}")
                        return
                else:
                    log("warn", f"  bundletool ({mode}): {r.stderr.strip()[:300]}")
            except subprocess.TimeoutExpired:
                log("warn", f"  bundletool ({mode}) timed out (300s)")
            except Exception as e:
                log("warn", f"  bundletool ({mode}) error: {e}")

        log("warn", "  All bundletool modes failed – trying apktool directly on AAB.")

    def _handle_apks_zip(self, zip_path: str):
        base = self._extract_from_apks_zip(zip_path)
        if base:
            self.target = base
            log("ok", f"  Base APK: {base}")
        else:
            log("warn", "  Could not locate base APK inside archive.")

    def _extract_from_apks_zip(self, zip_path: str):
        """
        Extract the base APK from an .apks / bundletool ZIP.
        Also extract all split APKs into self.split_apks so they can be
        re-signed later and passed to `adb install-multiple`.
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
                    apks = [n for n in nl if n.endswith(".apk") and "config." not in n]
                    if apks:
                        chosen = max(apks, key=lambda n: z.getinfo(n).file_size)
                if not chosen:
                    return None
                dest = os.path.join(out_dir, os.path.basename(chosen))
                with z.open(chosen) as sf, open(dest, "wb") as df:
                    shutil.copyfileobj(sf, df)

                # Extract all split APKs (config.arm64_v8a, config.en, etc.)
                splits = [n for n in nl if n.endswith(".apk") and n != chosen]
                self.split_apks = []
                for sp in splits:
                    sp_dest = os.path.join(out_dir, os.path.basename(sp))
                    with z.open(sp) as sf2, open(sp_dest, "wb") as df2:
                        shutil.copyfileobj(sf2, df2)
                    self.split_apks.append(sp_dest)
                if self.split_apks:
                    log("info",
                        f"  Extracted {len(self.split_apks)} split APK(s) "
                        f"(will be re-signed after build)", indent=1)
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
                # Extract remaining APKs as splits
                self.split_apks = []
                for sp in apks:
                    if sp == best:
                        continue
                    sp_dest = os.path.join(out_dir, os.path.basename(sp))
                    with z.open(sp) as sf2, open(sp_dest, "wb") as df2:
                        shutil.copyfileobj(sf2, df2)
                    self.split_apks.append(sp_dest)
                if self.split_apks:
                    log("info",
                        f"  {len(self.split_apks)} companion split APK(s) found",
                        indent=1)
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
        # Force full decode if TLS intercept is needed so AndroidManifest.xml is editable text
        decode_modes = [[]] if self.runtime_cfg.tls_intercept else [["--no-res"], []]
        for extra in decode_modes:
            t = threading.Thread(target=_spin, daemon=True); t.start()
            # Pass JAVA_OPTS if set (allows: JAVA_OPTS="-Xmx2g" for large APKs)
            java_opts = os.environ.get("JAVA_OPTS", "").split()
            cmd = (["java"] + java_opts +
                   ["-jar", APKTOOL_JAR, "d", self.target,
                    "-o", self.decompiled, "-f"] + extra)
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
        java_opts = os.environ.get("JAVA_OPTS", "").split()
        cmd = ["java"] + java_opts + ["-jar", APKTOOL_JAR, "b", vdir, "-o", out]
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
            log("ok", f"Unsigned [{label}]: {out} ({kb} KB)")
            # Post-build DEX sanity check: confirm at least one UNGUARD string
            # made it into the compiled DEX. If not, the patched smali was not
            # compiled (e.g. apktool used a cached version or wrong directory).
            if not _verify_dex_contains_patches(out):
                log("warn",
                    f"DEX verification: UNGUARD markers not found in rebuilt APK. "
                    f"Patches may not be active. Check --keep-work output.",
                    indent=1)
            return out
        # Expanded error capture: show ALL lines mentioning error/locals/smali/verify
        all_err = r.stderr.splitlines() + r.stdout.splitlines()
        err_lines = [l for l in all_err
                     if any(k in l.lower() for k in
                            ("error","smali","locals","verify","invalid","illegal",
                             "method","register","expected","found at"))
                     ][:10]
        log("err", f"Rebuild [{label}] failed:")
        for l in err_lines:
            log("err", l.strip(), indent=1)
        if not err_lines:
            # Show last 6 lines of stderr as fallback
            for l in r.stderr.splitlines()[-6:]:
                if l.strip():
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

        # jarsigner ONLY applies v1 (JAR) signatures.
        # Android 11+ (API 30+) requires v2 or higher; v1-only APKs will refuse to install.
        # Warn the user strongly if we have to fall back here.
        if not has_apksigner and has_jarsigner:
            # Try to detect minSdk from decompiled manifest
            try:
                mf_path = os.path.join(self.decompiled or "", "apktool.yml")
                if os.path.isfile(mf_path):
                    import re as _re
                    yml = open(mf_path).read()
                    m = _re.search(r"minSdkVersion:\s*'?(\d+)'?", yml)
                    if m and int(m.group(1)) >= 30:
                        log("warn",
                            f"SIGNING WARNING: jarsigner produces v1 (JAR) signatures only. "
                            f"minSdk={m.group(1)} ≥ 30 – this APK WILL NOT INSTALL on "
                            f"Android 11+. Install apksigner (Android SDK build-tools) "
                            f"and ensure it is on PATH.", indent=1)
            except Exception:
                pass
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
        slug      = patches_to_slug(patches)
        unsigned  = self.rebuild(vdir, slug)
        if not unsigned:
            return None
        signed_base = self.sign(unsigned, slug)
        base_name   = os.path.splitext(os.path.basename(self.target))[0]

        # ── Re-sign all companion split APKs ─────────────────────────────────
        signed_splits: list[str] = []
        for split_path in self.split_apks:
            sp_name   = os.path.splitext(os.path.basename(split_path))[0]
            sp_signed = self.sign(split_path, sp_name)
            if sp_signed and os.path.isfile(sp_signed):
                signed_splits.append(sp_signed)

        # ── Determine final output path ───────────────────────────────────────
        # --output-apk wins; else use output_dir
        output_apk = getattr(self, "output_apk", None)
        out_all    = getattr(self, "out_all", None)
        default_name = f"{base_name}_{slug}.apk"
        if output_apk:
            final = os.path.abspath(output_apk)
            os.makedirs(os.path.dirname(final) or ".", exist_ok=True)
        else:
            final = os.path.join(self.output_dir, default_name)

        # ── Merge splits → single APK when splits present ────────────────────
        merged_apk = None
        if signed_splits:
            log("info", f"Merging {len(signed_splits)} split(s) into base APK…")
            merged_apk = self._merge_splits_into_base(signed_base, signed_splits)

        # Pick what to copy to final destination
        source_apk = merged_apk if (merged_apk and os.path.isfile(merged_apk)) else signed_base

        try:
            shutil.copy(source_apk, final)
            if merged_apk and merged_apk != final:
                try: os.unlink(merged_apk)
                except: pass
        except shutil.SameFileError:
            final = source_apk

        if merged_apk and os.path.isfile(final):
            log("ok", f"Output (merged single APK): {C.G}{final}{C.RS}")
        else:
            log("ok", f"Output: {C.G}{final}{C.RS}")

        # ── --out-all: copy base + splits + merged into a directory ───────────
        if out_all:
            os.makedirs(out_all, exist_ok=True)
            # merged/base
            shutil.copy(final, os.path.join(out_all, os.path.basename(final)))
            log("ok", f"  [out-all] merged → {out_all}/", indent=1)
            # original signed splits (re-signed)
            for sp in signed_splits:
                sp_dest = os.path.join(out_all,
                    os.path.splitext(os.path.basename(sp))[0] + "_resigned.apk")
                shutil.copy(sp, sp_dest)
                log("ok", f"  [out-all] split  → {sp_dest}", indent=1)
            # original signed base
            base_dest = os.path.join(out_all, f"{base_name}_{slug}_base.apk")
            shutil.copy(signed_base, base_dest)
            log("ok", f"  [out-all] base   → {base_dest}", indent=1)

        # ── Fallback install hint when merge failed ───────────────────────────
        if signed_splits and not merged_apk:
            log("warn", "Split merge failed – use adb install-multiple:")
            split_outs = []
            for sp in signed_splits:
                sp_out = os.path.join(self.output_dir,
                    os.path.splitext(os.path.basename(sp))[0] + "_resigned.apk")
                shutil.copy(sp, sp_out)
                split_outs.append(sp_out)
            adb_cmd = "adb install-multiple " + " ".join(
                f'"{p}"' for p in [final] + split_outs)
            log("info", f"  {adb_cmd}", indent=1)

        return final

    # ── Main run ──────────────────────────────────────────────────────────────
    def run(self, patches: frozenset | None = None,
            detect_only: bool = False,
            report_path: str | None = None,
            merge_splits: bool = False) -> dict:
        banner()
        t0  = time.time()
        cfg = self.runtime_cfg
        self.merge_splits = merge_splits

        self.handle_split_apk()
        self.detect_engine()
        if not self.decompile():
            return {}
        self.detect_engine_post_decompile()
        self.analyze_with_androguard()

        log("head", "Smali Cache")
        cache = SmaliCache(self.decompiled)
        cache.load()

        # ── Obfuscation analysis (skipped entirely when --no-deob) ─────────────
        # With --no-deob this block is completely bypassed – no smali scan,
        # no progress bar, straight to API detection.
        obf_score = 0
        cust      = None
        if self.skip_deob:
            log("info", "Obfuscation analysis skipped (--no-deob).")
        else:
            log("head", "Obfuscation Analysis")
            _t1  = time.time()
            comm = CommercialObfuscationDetector(cache, self.target, self.workers)
            cust = CustomObfuscationEngine(cache, self.workers)
            comm.detect()
            cust.detect()
            obf_score = comm.score + cust.score
            log("ok", f"Obfuscation analysis: {time.time()-_t1:.1f}s  score={obf_score}/200")

            if obf_score > 10:
                _t2 = time.time()
                log("info", f"Score {obf_score} > 10 – running deobfuscation…")
                cust.deobfuscate()
                cache.invalidate()
                cache.load(show_progress=False)
                log("ok", f"Deobfuscation pass: {time.time()-_t2:.1f}s")
            else:
                log("info", "Obfuscation score ≤ 10 – deobfuscation not needed.")

        master = PatchEngine(self.decompiled, cache, self.workers)
        # Pass the requested patch categories so only relevant patterns are scanned.
        # detect_only=True → scan all (user wants the full picture)
        master.find_all(needed=None if detect_only else patches)

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
            server  = BridgeServer(cfg.bridge_port, on_event=console.on_event,
                                     bind_host=cfg.bridge_bind)
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
        # -- Merge splits into single APK if requested
        if getattr(self, 'merge_splits', False) and getattr(self, 'split_apks', []):
            _sp = (list(self.split_apks.values())
                   if isinstance(self.split_apks, dict) else list(self.split_apks))
            _mg = self._merge_splits_into_base(final, _sp)
            if _mg:
                final = _mg
                log('ok', f'Merged APK (single install): {C.G}{final}{C.RS}')

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
            _p(r"Lcom/pairip/licensecheck/",
               "integrity", "PAIRIP",            "PairIP license system (very common in Unity games)"),
            _p(r"initializeLicenseCheck|scheduleRepeatedLicenseCheck|"
               r"reportSuccessfulLicenseCheck",
               "integrity", "PAIRIP_METHODS",    "PairIP license lifecycle methods"),

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
#  UnGuard v3.3.1  ─  RUNTIME ANALYSIS LAYER
#  All classes in this section are optional modules activated by CLI flags.
#  The base static-patch pipeline is completely unaffected when
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
    fake_google_verify : bool = False   # new: intercept Google validation and return success
    bridge_port   : int  = 17185   # TCP port for APK ↔ UnGuard event bridge
    proxy_port    : int  = 8080    # local MITM proxy port (future extension)
    profile_db    : str  = "unguard_profile.db"
    rules_file    : str  = "unguard_rules.json"
    bridge_bind   : str  = "127.0.0.1"  # --bridge-bind (0.0.0.0 for Termux LAN)

    @property
    def any_runtime(self) -> bool:
        """True if any runtime feature is enabled (bridge must be started)."""
        return (self.trace_runtime or self.tls_intercept or self.learn
                or self.hybrid or self.net_debug or self.fake_google_verify)

    @property
    def needs_bridge(self) -> bool:
        """True when we must inject UGBridge and start the server."""
        return self.trace_runtime or self.learn or self.net_debug or self.fake_google_verify

    @property
    def needs_net_interceptor(self) -> bool:
        """True when we must inject the OkHttp interceptor (logging + fake responses)."""
        return self.net_debug or self.learn or self.fake_google_verify

# ──────────────────────────────────────────────────────────────────────────────
#  Smali + XML templates injected into the decompiled APK
#  These are verbatim Dalvik smali – every register, catch block, and
#  type descriptor has been verified to pass apktool's assembler.
# ──────────────────────────────────────────────────────────────────────────────

# ─── UGBridge.smali (fully verified) ─────────────────────────────────────────
_SMALI_UGBRIDGE = """\
.class public Lcom/ug/rt/UGBridge;
.super Ljava/lang/Object;
.source "UGBridge.java"

.field private static volatile sock:Ljava/net/Socket;
.field private static volatile wtr:Ljava/io/BufferedWriter;
.field private static volatile active:Z

.method static constructor <clinit>()V
    .locals 1
    const/4 v0, 0x0
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    return-void
.end method

.method public static connect(Ljava/lang/String;I)V
    .locals 5
    :try_start_0
    new-instance v0, Ljava/net/Socket;
    invoke-direct {v0, p0, p1}, Ljava/net/Socket;-><init>(Ljava/lang/String;I)V
    sput-object v0, Lcom/ug/rt/UGBridge;->sock:Ljava/net/Socket;

    invoke-virtual {v0}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v1

    new-instance v2, Ljava/io/OutputStreamWriter;
    const-string v3, "UTF-8"
    invoke-direct {v2, v1, v3}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/lang/String;)V

    new-instance v4, Ljava/io/BufferedWriter;
    invoke-direct {v4, v2}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V
    sput-object v4, Lcom/ug/rt/UGBridge;->wtr:Ljava/io/BufferedWriter;

    const/4 v0, 0x1
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    :try_end_0
    .catch Ljava/lang/Throwable; { :try_start_0 .. :try_end_0 } :catch_0
:catch_0
    return-void
.end method

.method public static connectBackground(Ljava/lang/String;I)V
    .locals 1
    :try_start_1
    new-instance v0, Lcom/ug/rt/UGBridge$ConnThread;
    invoke-direct {v0, p0, p1}, Lcom/ug/rt/UGBridge$ConnThread;-><init>(Ljava/lang/String;I)V
    invoke-virtual {v0}, Lcom/ug/rt/UGBridge$ConnThread;->start()V
    :try_end_1
    .catch Ljava/lang/Throwable; { :try_start_1 .. :try_end_1 } :catch_1
:catch_1
    return-void
.end method

.method public static send(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4
    sget-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
    if-nez v0, :cond_0
    return-void
    :cond_0
    :try_start_2
    sget-object v1, Lcom/ug/rt/UGBridge;->wtr:Ljava/io/BufferedWriter;
    if-nez v1, :cond_1
    return-void
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V
    const-string v3, "{\\"t\\":\\""
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    const-string v3, "\\",\\"d\\":"
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    const-string v3, "}}"
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/BufferedWriter;->write(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/BufferedWriter;->newLine()V
    invoke-virtual {v1}, Ljava/io/BufferedWriter;->flush()V
    :try_end_2
    .catch Ljava/lang/Throwable; { :try_start_2 .. :try_end_2 } :catch_2
    goto :goto_0
:catch_2
    const/4 v0, 0x0
    sput-boolean v0, Lcom/ug/rt/UGBridge;->active:Z
:goto_0
    return-void
.end method

.method public static onLifecycle(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{\\"cls\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\",\\"ev\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\"}}"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "LC"
    invoke-static {v2, v1}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method

.method public static onException(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{\\"cls\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\",\\"msg\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\"}}"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "EX"
    invoke-static {v2, v1}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method

.method public static onStorage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "{\\"type\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\",\\"key\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\",\\"val\\":\\""
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    const-string v1, "\\"}}"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "ST"
    invoke-static {v2, v1}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method
"""

# ─── UGBridge$ConnThread.smali (fully verified) ─────────────────────────────
_SMALI_UGBRIDGE_CONNTHREAD = """\
.class Lcom/ug/rt/UGBridge$ConnThread;
.super Ljava/lang/Thread;
.source "UGBridge.java"

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/ug/rt/UGBridge;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = "ConnThread"
.end annotation

.field host:Ljava/lang/String;
.field port:I

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V
    iput-object p1, p0, Lcom/ug/rt/UGBridge$ConnThread;->host:Ljava/lang/String;
    iput p2, p0, Lcom/ug/rt/UGBridge$ConnThread;->port:I
    return-void
.end method

.method public run()V
    .locals 2
    iget-object v0, p0, Lcom/ug/rt/UGBridge$ConnThread;->host:Ljava/lang/String;
    iget v1, p0, Lcom/ug/rt/UGBridge$ConnThread;->port:I
    invoke-static {v0, v1}, Lcom/ug/rt/UGBridge;->connect(Ljava/lang/String;I)V
    return-void
.end method
"""

# ─── UGNetInterceptor.smali (fully verified) ────────────────────────────────
_SMALI_UGNET_INTERCEPTOR = """\
.class public Lcom/ug/rt/UGNetInterceptor;
.super Ljava/lang/Object;
.source "UGNetInterceptor.java"
.implements Lokhttp3/Interceptor;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;
    .locals 8
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    invoke-interface {p1}, Lokhttp3/Interceptor$Chain;->request()Lokhttp3/Request;
    move-result-object v0

    invoke-virtual {v0}, Lokhttp3/Request;->url()Lokhttp3/HttpUrl;
    move-result-object v1
    invoke-virtual {v1}, Lokhttp3/HttpUrl;->toString()Ljava/lang/String;
    move-result-object v1

    const-string v2, "play.googleapis.com"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v2
    if-nez v2, :cond_build_fake_response

    const-string v2, "androidpublisher"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v2
    if-nez v2, :cond_build_fake_response

    const-string v2, "licensing"
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v2
    if-nez v2, :cond_build_fake_response

    goto :cond_proceed

:cond_build_fake_response
    const-string v2, "application/json"
    invoke-static {v2}, Lokhttp3/MediaType;->parse(Ljava/lang/String;)Lokhttp3/MediaType;
    move-result-object v2

    const-string v4, "{\\"isLicensed\\":true,\\"purchaseState\\":0,\\"consumptionState\\":1}"
    invoke-static {v2, v4}, Lokhttp3/ResponseBody;->create(Lokhttp3/MediaType;Ljava/lang/String;)Lokhttp3/ResponseBody;
    move-result-object v3

    new-instance v4, Lokhttp3/Response$Builder;
    invoke-direct {v4}, Lokhttp3/Response$Builder;-><init>()V
    const/16 v5, 0xc8
    invoke-virtual {v4, v5}, Lokhttp3/Response$Builder;->code(I)Lokhttp3/Response$Builder;
    move-result-object v4
    const-string v5, "OK"
    invoke-virtual {v4, v5}, Lokhttp3/Response$Builder;->message(Ljava/lang/String;)Lokhttp3/Response$Builder;
    move-result-object v4
    invoke-virtual {v4, v0}, Lokhttp3/Response$Builder;->request(Lokhttp3/Request;)Lokhttp3/Response$Builder;
    move-result-object v4
    const-string v5, "Connection"
    const-string v6, "close"
    invoke-virtual {v4, v5, v6}, Lokhttp3/Response$Builder;->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Response$Builder;
    move-result-object v4
    invoke-virtual {v4, v3}, Lokhttp3/Response$Builder;->body(Lokhttp3/ResponseBody;)Lokhttp3/Response$Builder;
    move-result-object v4
    invoke-virtual {v4}, Lokhttp3/Response$Builder;->build()Lokhttp3/Response;
    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V
    const-string v4, "{\\"url\\":\\""
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    const-string v4, "\\",\\"m\\":\\""
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {v0}, Lokhttp3/Request;->method()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    const-string v4, "\\",\\"s\\":200}}"
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3

    const-string v4, "NET"
    invoke-static {v4, v3}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V

    return-object v2

:cond_proceed
    invoke-interface {p1, v0}, Lokhttp3/Interceptor$Chain;->proceed(Lokhttp3/Request;)Lokhttp3/Response;
    move-result-object v2

    invoke-virtual {v2}, Lokhttp3/Response;->code()I
    move-result v3
    invoke-static {v3}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V
    const-string v5, "{\\"url\\":\\""
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    const-string v5, "\\",\\"m\\":\\""
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v0}, Lokhttp3/Request;->method()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    const-string v5, "\\",\\"s\\":"
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    const-string v5, "}}"
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v4

    const-string v5, "NET"
    invoke-static {v5, v4}, Lcom/ug/rt/UGBridge;->send(Ljava/lang/String;Ljava/lang/String;)V

    return-object v2
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
      • UGNetInterceptor.smali + OkHttp addInterceptor() hooks (--net-debug / --learn / --fake-google-verify)
      • network_security_config.xml (--tls-intercept)
      • lifecycle hooks in Activity / Fragment onCreate/onDestroy (--trace-runtime)
      • entry hooks in sensitive smali methods (--trace-runtime)
      • connectBackground() call at app entry point (all bridge modes)
    """
    BRIDGE_PKG   = "com/ug/rt"
    BRIDGE_CLS   = "Lcom/ug/rt/UGBridge;"
    NET_CLS      = "Lcom/ug/rt/UGNetInterceptor;"

    # ── Register helpers (Dalvik 4-bit limit: v0-v15 only for const-string etc.) ─
    def _get_param_slots_and_static(self, method_line: str) -> tuple[int, bool]:
        """Extract parameter register slots and static-flag from a .method line."""
        m = re.search(r"\.method\s+(.*?)([^(]+)(\([^)]*\).*)", method_line)
        if not m:
            return 0, False
        is_static = "static" in m.group(1)
        slots     = _count_jvm_params(m.group(3))
        return slots, is_static

    def _find_free_low_reg_pair(self, lines: list[str],
                                method_start: int, scan_end: int,
                                occupied: int) -> int | None:
        """Find lowest R where vR and vR+1 are both in 0-15 and not used
        between method_start..scan_end. Returns R or None."""
        used: set[int] = set()
        for k in range(method_start + 1, min(scan_end, len(lines))):
            for hit in re.finditer(r"\bv(\d+)\b", lines[k]):
                used.add(int(hit.group(1)))
        for r in range(occupied, 15):   # r+1 must be <= 15
            if r not in used and (r + 1) not in used:
                return r
        return None

    def _bump_and_get_pair(self, lines: list[str],
                           method_start: int, scan_end: int
                           ) -> tuple[int | None, int]:
        """
        Locate .locals OR .registers, find a free (r0,r1) pair in v0-v15,
        bump the directive, return (r0, directive_line_idx).
        Returns (None, -1) when no suitable pair exists or cap hit.

        .registers N   – N = total registers (locals + params)
        .locals N      – N = local-only registers; params follow at vN..vN+params-1
        We normalise .registers → effective .locals before searching.
        """
        param_slots, is_static = self._get_param_slots_and_static(lines[method_start])
        implicit_this = 0 if is_static else 1
        total_params  = param_slots + implicit_this

        for j in range(method_start + 1, min(method_start + 12, len(lines))):
            # .locals N
            lm_l = re.match(r"([ \t]+\.locals\s+)(\d+)", lines[j])
            # .registers N
            lm_r = re.match(r"([ \t]+\.registers\s+)(\d+)", lines[j])

            if lm_l:
                old_locals = int(lm_l.group(2))
                if old_locals + 2 > 250:
                    return None, -1
                occupied = total_params
                r0 = self._find_free_low_reg_pair(lines, method_start, scan_end, occupied)
                if r0 is None:
                    return None, -1
                new_locals = max(old_locals, r0 + 2)
                lines[j] = f"{lm_l.group(1)}{new_locals}\n"
                return r0, j

            elif lm_r:
                # .registers N means N total: first N-params are locals, last
                # params are the parameter registers.
                old_regs   = int(lm_r.group(2))
                old_locals = max(0, old_regs - total_params)
                if old_locals + 2 > 250:
                    return None, -1
                # Parameter registers live at v(old_locals)..v(old_locals+params-1)
                # New locals start at 0; parameters shift up by 2.
                # We pick r0 from the local range ONLY (below old_locals).
                occupied = 0   # locals start at v0
                r0 = self._find_free_low_reg_pair(lines, method_start, scan_end, occupied)
                # Ensure r0, r0+1 are in the local range and ≤ 15
                if r0 is None or r0 + 1 >= min(old_locals + 2, 16):
                    return None, -1
                new_regs = old_regs + 2
                lines[j] = f"{lm_r.group(1)}{new_regs}\n"
                return r0, j

        return None, -1

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

        # 2. Optionally write + hook OkHttp network interceptor (logging + fake responses)
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
            _SMALI_UGBRIDGE, encoding="utf-8")
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
            # Safety check: Prevent overwriting compiled binary XML with string ops
            with open(manifest, "rb") as f:
                is_binary = f.read(4) == b"\x03\x00\x08\x00"

            if is_binary:
                log("warn", "AndroidManifest.xml is binary! Cannot inject TLS config. "
                    "(Use --tls-intercept to force full decode)", indent=1)
            else:
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
                end_idx = next((k for k in range(ms + 1, len(lines))
                                if lines[k].strip() == ".end method"), None)
                scan_end = end_idx if end_idx else min(ms + 80, len(lines))
                tmp_r0, _ = self._bump_and_get_pair(lines, ms, scan_end)
                if tmp_r0 is None:
                    i += 1; continue
                tmp_reg = f"v{tmp_r0}"
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
                # Find .end method to bound the scan
                end_idx = next((k for k in range(i + 1, len(lines))
                                if lines[k].strip() == ".end method"), None)
                scan_end = end_idx if end_idx else min(i + 60, len(lines))
                r0, _ = self._bump_and_get_pair(lines, i, scan_end)
                if r0 is None:
                    log("warn", f"Trace: skip {method} in {sf.name} L{i}: "
                        "no free register pair in v0-v15", indent=2)
                    i += 1; continue
                r1 = r0 + 1
                # const-string is 4-bit: v0-v15 always valid (r0 ≤ 14 guaranteed)
                hook = [
                    f'    const-string v{r0}, "{cls_name}"\n',
                    f'    const-string v{r1}, "{method}"\n',
                    f'    invoke-static {{v{r0}, v{r1}}}, '
                    f'{self.BRIDGE_CLS}->onLifecycle('
                    f'Ljava/lang/String;Ljava/lang/String;)V\n',
                ]
                # Insert after .locals line (j is returned from _bump_and_get_pair
                # but we need it; redo scan to find .locals line index)
                for j in range(i + 1, min(i + 12, len(lines))):
                    if re.match(r"[ \t]+\.locals\s+\d+", lines[j]):
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
                end_idx = next((k for k in range(i + 1, len(lines))
                                if lines[k].strip() == ".end method"), None)
                scan_end = end_idx if end_idx else min(i + 60, len(lines))
                r0, _ = self._bump_and_get_pair(lines, i, scan_end)
                if r0 is None:
                    i += 1; continue
                r1 = r0 + 1
                hook = [
                    f'    const-string v{r0}, "{cls_name}"\n',
                    f'    const-string v{r1}, "SENSITIVE:{mname}"\n',
                    f'    invoke-static {{v{r0}, v{r1}}}, '
                    f'{self.BRIDGE_CLS}->onLifecycle('
                    f'Ljava/lang/String;Ljava/lang/String;)V\n',
                ]
                for j in range(i + 1, min(i + 12, len(lines))):
                    if re.match(r"[ \t]+\.locals\s+\d+", lines[j]):
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
                end_idx = next((k for k in range(i + 1, len(lines))
                                if lines[k].strip() == ".end method"), None)
                scan_end = end_idx if end_idx else min(i + 60, len(lines))
                r0, _ = self._bump_and_get_pair(lines, i, scan_end)
                if r0 is None:
                    log("warn",
                        f"Bridge: skip connect in {sf.name} L{i}: "
                        "no free register pair in v0-v15", indent=2)
                    i += 1; continue
                r1 = r0 + 1
                port_lit = f"0x{self.cfg.bridge_port:x}"
                hook = [
                    f'    const-string v{r0}, "127.0.0.1"\n',
                    f'    const/16 v{r1}, {port_lit}\n',
                    f'    invoke-static {{v{r0}, v{r1}}}, '
                    f'{self.BRIDGE_CLS}->connectBackground('
                    f'Ljava/lang/String;I)V\n',
                ]
                for j in range(i + 1, min(i + 12, len(lines))):
                    if re.match(r"[ \t]+\.locals\s+\d+", lines[j]):
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
        """
        Locate the best smali file to inject connectBackground() into.
        Priority:
          1. android:name Application class from manifest (best)
          2. MAIN/LAUNCHER activity from manifest
          3. Any smali extending Application in all smali dirs (Unity fallback)
          4. Any smali extending UnityPlayerActivity or GameActivity
        """
        manifest = self.base / "AndroidManifest.xml"
        if manifest.is_file():
            mt = manifest.read_text(encoding="utf-8", errors="ignore")
            # 1. Application subclass
            m = re.search(r'<application[^>]+android:name="([^"]+)"', mt)
            if m:
                p = self._resolve_class(m.group(1))
                if p:
                    return p
            # 2. All activities in manifest – try each until one resolves
            for m in re.finditer(r'<activity[^>]+android:name="([^"]+)"', mt):
                p = self._resolve_class(m.group(1))
                if p:
                    return p

        # 3. Scan smali dirs for any class that extends Application
        _APP_SUPER_RE = re.compile(
            r"\.super\s+Landroid/app/Application;|"
            r"\.super\s+Landroidx/multidex/MultiDexApplication;|"
            r"\.super\s+Landroid/app/Application"
        )
        _UNITY_SUPER_RE = re.compile(
            r"\.super\s+Lcom/unity3d/player/UnityPlayer(?:Activity|GameActivity)?;"
            r"|\.super\s+Lcom/unity3d/player/GameActivity;"
        )
        candidates = []
        for sdir in self._smali_dirs():
            for sf in sdir.rglob("*.smali"):
                try:
                    txt = sf.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if _APP_SUPER_RE.search(txt):
                    candidates.insert(0, sf)   # Application subclass takes priority
                elif _UNITY_SUPER_RE.search(txt):
                    candidates.append(sf)       # Unity activity as fallback
        if candidates:
            log("info",
                f"Bridge: using fallback entry point: {candidates[0].name}",
                indent=1)
            return candidates[0]
        return None

    def _resolve_class(self, cls: str) -> Path | None:
        cls = cls.lstrip(".").replace(".", "/") + ".smali"
        for sdir in self._smali_dirs():
            p = sdir / cls
            if p.is_file():
                return p
        return None

    def _bump_locals_get_free_reg(self, lines: list[str], method_start: int,
                                   target: int) -> str:
        """Legacy shim → delegates to _bump_and_get_pair.
        Returns '' if no free register found, else 'vN' for N in 0-15."""
        r0, _ = self._bump_and_get_pair(lines, method_start, target)
        return f"v{r0}" if r0 is not None else ""
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
    def __init__(self, port: int, on_event: _Callable[[dict], None],
                 bind_host: str = "127.0.0.1"):
        self.port      = port
        self.bind_host = bind_host
        self.on_event  = on_event
        self._srv: _socket.socket | None = None
        self._stop    = threading.Event()
        self._thread: threading.Thread | None = None
        self.connected_clients = 0

    def start(self):
        self._srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        try:
            self._srv.bind((self.bind_host, self.port))
        except OSError as e:
            log("err", f"Bridge: cannot bind {self.bind_host}:{self.port}: {e}")
            raise
        self._srv.listen(8)
        self._srv.settimeout(1.0)
        self._thread = threading.Thread(
            target=self._accept_loop, name="UGBridgeSrv", daemon=True)
        self._thread.start()
        log("ok",  f"Bridge server listening on {self.bind_host}:{self.port}")
        if self.bind_host == "127.0.0.1":
            log("info",
                f"  Forward from device: adb forward tcp:{self.port} tcp:{self.port}",
                indent=1)
            log("info",
                "  Or use --bridge-bind 0.0.0.0 if device and PC share LAN "
                "(less secure).", indent=1)
        else:
            log("warn",
                f"  Bridge bound to {self.bind_host} – accessible from entire "
                f"local network. Ensure firewall rules are in place.", indent=1)

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

    if cfg.fake_google_verify:
        log("info", "Fake Google Verify mode:")
        log("info", "  Interceptor will return hardcoded success for requests to:", indent=1)
        log("info", "    * play.googleapis.com", indent=2)
        log("info", "    * androidpublisher", indent=2)
        log("info", "    * licensing", indent=2)
        log("info", "  Modify the JSON payload in UGNetInterceptor.smali if needed.", indent=1)

    if not cfg.needs_bridge and not cfg.tls_intercept and not cfg.fake_google_verify:
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
        "  python unguard.py app.apk --patch all --fake-google-verify\n"
        "  python unguard.py app.apk --patch all --learn\n"
        "  python unguard.py app.apk --patch all --hybrid\n"
        "  python unguard.py app.apk --patch all --learn --net-debug --fake-google-verify\n"
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
    og.add_argument("-o", "--output", default=None, metavar="DIR",
        help="Output directory for all produced files (default: current dir)")
    og.add_argument("--output-apk", default=None, metavar="FILE.apk",
        help="Write final merged/patched APK to this exact path")
    og.add_argument("--out-all", default=None, metavar="DIR",
        help="Copy base APK, all split APKs, and merged APK into this directory")
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
    fg.add_argument("--merge-splits", action="store_true", default=False,
        help="Merge base + split APKs into one installable APK. "
             "Copies lib/ and assets/ from each split into base, then re-signs.")
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
    rg.add_argument("--fake-google-verify", action="store_true",
        help="Intercept Google validation requests (licensing, purchase verify) "
             "and return a hardcoded success response. Works with --tls-intercept.")
    rg.add_argument("--learn", action="store_true",
        help="Observe app behaviour and save a profile to --profile-db. "
             "Auto-discovers premium gates, analytics, storage tokens.")
    rg.add_argument("--hybrid", action="store_true",
        help="Apply rules from a previous --learn session as static patches.")
    rg.add_argument("--net-debug", action="store_true",
        help="Stream all OkHttp network requests/responses to console.")
    def _valid_port(v):
        try:
            p = int(v)
            if 1 <= p <= 65535: return p
        except ValueError: pass
        raise argparse.ArgumentTypeError(f"Port must be 1-65535, got: {v!r}")

    rg.add_argument("--bridge-port", type=_valid_port, default=17185, metavar="PORT",
        help="TCP port for the APK→UnGuard event bridge. "
             "Default 17185. Run: adb forward tcp:PORT tcp:PORT")
    rg.add_argument("--proxy-port", type=_valid_port, default=8080, metavar="PORT",
        help="Local proxy port for TLS intercept (mitmproxy/Burp). Default 8080.")
    rg.add_argument("--profile-db", default="unguard_profile.db", metavar="FILE",
        help="SQLite profile database path (--learn / --hybrid).")
    rg.add_argument("--rules-file", default="unguard_rules.json", metavar="FILE",
        help="JSON rules file path (--learn writes, --hybrid reads).")
    rg.add_argument("--bridge-bind", default="127.0.0.1", metavar="HOST",
        help="Bridge server bind address. Default 127.0.0.1 (secure). "
             "Use 0.0.0.0 for Termux when bridging from a PC over USB adb forward.")

    ig = parser.add_argument_group("Device (optional)")
    ig.add_argument("--install", action="store_true",
        help="After build, install the patched APK (and splits) on connected "
             "Android device via adb. Uses adb install or adb install-multiple.")
    ig.add_argument("--adb", default="adb", metavar="PATH",
        help="Path to adb binary (default: adb from PATH).")

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
        fake_google_verify = getattr(args, "fake_google_verify", False),
        bridge_port   = getattr(args, "bridge_port",   17185),
        proxy_port    = getattr(args, "proxy_port",    8080),
        profile_db    = getattr(args, "profile_db",    "unguard_profile.db"),
        rules_file    = getattr(args, "rules_file",    "unguard_rules.json"),
        bridge_bind   = getattr(args, "bridge_bind",   "127.0.0.1"),
    )
    if rt_cfg.any_runtime:
        active = [f for f in ("trace_runtime","tls_intercept","learn",
                               "hybrid","net_debug","fake_google_verify") if getattr(rt_cfg, f)]
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
    patcher.output_apk = getattr(args, "output_apk", None)
    patcher.out_all    = getattr(args, "out_all", None)

    ok = False
    try:
        results = patcher.run(
            patches      = patches,
            detect_only  = args.detect_only,
            report_path  = args.report,
            merge_splits = getattr(args, "merge_splits", False),
        )
        if args.detect_only:
            ok = bool(results)
        else:
            out = results.get("output")
            ok  = bool(out and os.path.exists(out))
            # ── --install: push patched APK(s) to device via adb ─────────
            if ok and getattr(args, "install", False):
                adb_bin = getattr(args, "adb", "adb")
                # Find any re-signed splits in output dir
                signed_splits = [
                    os.path.join(patcher.output_dir,
                                 os.path.splitext(os.path.basename(sp))[0]
                                 + "_resigned.apk")
                    for sp in patcher.split_apks
                ]
                signed_splits = [s for s in signed_splits if os.path.isfile(s)]
                if signed_splits:
                    cmd = [adb_bin, "install-multiple", "-r", out] + signed_splits
                    label_str = f"base + {len(signed_splits)} split(s)"
                else:
                    cmd = [adb_bin, "install", "-r", out]
                    label_str = "base APK"
                log("info", f"Installing {label_str} via adb…")
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if r.returncode == 0:
                        log("ok", "adb install SUCCESS")
                    else:
                        log("err", f"adb install failed: {r.stderr.strip()[:300]}")
                except FileNotFoundError:
                    log("err",
                        f"adb not found at '{adb_bin}'. Install Android SDK platform-tools.")
                except subprocess.TimeoutExpired:
                    log("err", "adb install timed out (120s).")
    except KeyboardInterrupt:
        log("warn", "Interrupted.")
    finally:
        if not args.keep_work:
            patcher.cleanup()

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()