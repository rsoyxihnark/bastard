
import os, sys, time, json, csv, re, threading, queue, traceback
import subprocess, tempfile, ctypes
import ctypes.wintypes as wt
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont, scrolledtext

try: import winreg
except ImportError: winreg = None

HAVE_PSUTIL = HAVE_WMI = HAVE_ETW = HAVE_PROCMON = HAVE_WATCHDOG = False
try: import psutil; HAVE_PSUTIL = True
except ImportError: pass
try: import pythoncom, wmi; HAVE_WMI = True
except ImportError: pythoncom = None
try: import etw as etw_mod; HAVE_ETW = True
except ImportError: pass
try: from procmon_parser import ProcmonLogsReader; HAVE_PROCMON = True
except ImportError: pass
try: from watchdog.observers import Observer; from watchdog.events import FileSystemEventHandler; HAVE_WATCHDOG = True
except ImportError: pass

TAG = "V3FINAL"
CREATE_NO_WINDOW = 0x08000000

def _run_silent(cmd, timeout=30, **kw):
    if os.name == "nt":
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            kw.setdefault("startupinfo", si)
            kw.setdefault("creationflags", CREATE_NO_WINDOW)
        except Exception: pass
    return subprocess.run(cmd, timeout=timeout, **kw)

def _get_desktop():
    try:
        up = Path(os.environ.get('USERPROFILE', str(Path.home())))
        for c in (up / 'Desktop', up / 'OneDrive' / 'Desktop', up / 'Masaüstü'):
            if c.is_dir(): return c
    except: pass
    return Path.home()

DESKTOP = _get_desktop()
STARTUP_LOG = DESKTOP / f"{TAG}_startup.log"
LIVE_LOG = DESKTOP / f"{TAG}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

_log_lock = threading.Lock()
def _write_log(path, msg):
    with _log_lock:
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")
                f.flush()
        except: pass

def startup_log(msg): _write_log(STARTUP_LOG, msg)
def live_log(msg): _write_log(LIVE_LOG, msg)

def _install_excepthook():
    def _hook(t, v, tb):
        txt = ''.join(traceback.format_exception(t, v, tb))
        startup_log(f"UNCAUGHT: {txt}")
        live_log(f"[FATAL] {txt}")
    sys.excepthook = _hook
_install_excepthook()

def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False

def relaunch_as_admin():
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        exe = sys.executable
        if exe.lower().endswith("python.exe"):
            cand = exe[:-10] + "pythonw.exe"
            if os.path.isfile(cand): exe = cand
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f'"{script}" {params}', None, 1)
        return int(r) > 32
    except Exception as e:
        startup_log(f"Elevation failed: {e}")
        return False

class UEvent:
    __slots__ = ("ts", "source", "type", "pid", "detail", "level")
    def __init__(self, source, type_, pid, detail, level="INFO"):
        self.ts = time.time()
        self.source = source
        self.type = type_
        self.pid = pid if pid else 0
        self.detail = str(detail)[:1500]
        self.level = level

    def fmt_time(self):
        return datetime.fromtimestamp(self.ts).strftime("%H:%M:%S.%f")[:-3]

class EventBus:
    def __init__(self, maxlen=3000):
        self.q = queue.Queue()
        self.maxlen = maxlen
        self.dropped = 0
        self.lock = threading.Lock()
        self._size = 0
        self.history = deque(maxlen=50000)
    def put(self, ev):
        self.history.append(ev)
        with self.lock:
            if self._size >= self.maxlen:
                try: self.q.get_nowait(); self._size -= 1; self.dropped += 1
                except: pass
            try: self.q.put_nowait(ev); self._size += 1
            except: pass
    def drain(self, maxn=500):
        out = []
        for _ in range(maxn):
            try:
                out.append(self.q.get_nowait())
                with self.lock: self._size = max(0, self._size - 1)
            except queue.Empty: break
        return out

BUS = EventBus()
class SourceStatus:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()
    def set(self, name, state, note=""):
        with self.lock: self.data[name] = (state, note)
        live_log(f"[status] {name} = {state} {note}")
    def get(self):
        with self.lock: return dict(self.data)
STATUS = SourceStatus()

def emit(source, type_, detail, pid=0, level="INFO"):
    ev = UEvent(source, type_, pid, detail, level)
    BUS.put(ev)
    live_log(f"[{level}] {source}/{type_} {detail[:400]}")
    return ev

def _safe_val(val, typ):
    if winreg and typ == winreg.REG_BINARY:
        if not val: return "<empty binary>"
        if len(val) > 64: return f"<binary {len(val)} bytes>"
        return "0x" + val.hex()
    s = str(val)
    return s[:200] + "..." if len(s) > 200 else s

def _reg_enum_tree(root, subkey, max_depth=5, _d=0):
    if winreg is None or _d > max_depth: return {}
    out = {}
    try: h = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
    except: return {}
    try:
        n_sub, n_val, _ = winreg.QueryInfoKey(h)
        for i in range(n_val):
            try:
                name, val, typ = winreg.EnumValue(h, i)
                out["v:" + name] = _safe_val(val, typ)
            except: pass
        for i in range(n_sub):
            try:
                sn = winreg.EnumKey(h, i)
                child = _reg_enum_tree(root, f"{subkey}\\{sn}", max_depth, _d + 1)
                for k, v in child.items(): out[f"{sn}\\{k}"] = v
            except: pass
    finally:
        try: winreg.CloseKey(h)
        except: pass
    return out

def reg_get(root, path, name):
    if winreg is None: return None
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as h:
            v, _ = winreg.QueryValueEx(h, name)
            return v
    except: return None

class StopFlag:
    def __init__(self): self.evt = threading.Event()
    def set(self): self.evt.set()
    def is_set(self): return self.evt.is_set()
    def wait(self, t): return self.evt.wait(t)

def collector_regpoll(stop):
    if not winreg: return STATUS.set("RegPoll", "red", "winreg yok")
    targets = [
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Lock Screen"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"),
    ]
    STATUS.set("RegPoll", "green", "polling")
    prev = {(tg, p): _reg_enum_tree(rt, p) for tg, rt, p in targets}
    while not stop.is_set():
        for tg, rt, p in targets:
            cur = _reg_enum_tree(rt, p)
            old = prev.get((tg, p), {})
            for k, v in cur.items():
                if old.get(k, "__MISS__") != v:
                    oldv = old.get(k, "<yok>")
                    nm = k[2:] if k.startswith("v:") else k
                    lvl = "MEDIUM" if "wallpaper" in p.lower() else "INFO"
                    emit("RegPoll", "Registry", f"{tg}\\{p} [{nm}]: {oldv} -> {v}", level=lvl)
            for k in old:
                if k not in cur:
                    nm = k[2:] if k.startswith("v:") else k
                    emit("RegPoll", "Registry", f"{tg}\\{p} [{nm}] deleted", level="MEDIUM")
            prev[(tg, p)] = cur
        stop.wait(1.0)

def collector_filewatch(stop):
    dirs = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Themes"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\Themes"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe")
    ]
    dirs = [d for d in dirs if os.path.isdir(d)]
    if not dirs: return STATUS.set("FileWatch", "red", "klasor yok")

    if HAVE_WATCHDOG:
        class H(FileSystemEventHandler):
            def on_any_event(self, e):
                if e.is_directory: return
                src = getattr(e, "src_path", "")
                emit("FileWatch", "File", f"{e.event_type} {src}", level="MEDIUM")
        obs = Observer(); h = H()
        for d in dirs:
            try: obs.schedule(h, d, recursive=True)
            except: pass
        obs.start()
        STATUS.set("FileWatch", "green", f"watchdog {len(dirs)}")
        while not stop.is_set(): stop.wait(1.0)
        obs.stop(); obs.join(timeout=2)
    else:
        def snap(d):
            out = {}
            try:
                for nm in os.listdir(d):
                    try: st = os.stat(os.path.join(d, nm)); out[nm] = (st.st_size, int(st.st_mtime))
                    except: out[nm] = (0,0)
            except: pass
            return out
        prev = {d: snap(d) for d in dirs}
        STATUS.set("FileWatch", "yellow", "manual poll")
        while not stop.is_set():
            for d in dirs:
                cur = snap(d); old = prev[d]
                for k, v in cur.items():
                    if k not in old: emit("FileWatch", "File", f"created {d}\\{k}", level="MEDIUM")
                    elif old[k] != v: emit("FileWatch", "File", f"modified {d}\\{k}", level="MEDIUM")
                for k in old:
                    if k not in cur: emit("FileWatch", "File", f"deleted {d}\\{k}", level="MEDIUM")
                prev[d] = cur
            stop.wait(1.0)

def collector_proc(stop):
    watch = {"photos.exe", "runtimebroker.exe", "dllhost.exe", "systemsettings.exe", "explorer.exe",
             "sihost.exe", "backgroundtaskhost.exe", "applicationframehost.exe", "lockapp.exe"}
    seen = set()
    if HAVE_PSUTIL:
        STATUS.set("Proc", "green", "psutil")
        for p in psutil.process_iter(["pid"]): seen.add(p.pid)
        while not stop.is_set():
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if p.pid not in seen:
                        seen.add(p.pid)
                        nm = (p.info["name"] or "").lower()
                        cmd = " ".join(p.info["cmdline"] or [])
                        if nm in watch or any(k in cmd.lower() for k in ("wallpaper", "theme", "lockscreen")):
                            emit("Proc", "Process", f"Start {nm} cmd={cmd}", pid=p.pid, level="MEDIUM")
                except: pass
            stop.wait(1.5)
    else:
        STATUS.set("Proc", "yellow", "Toolhelp32 fallback")
        TH32CS_SNAPPROCESS = 0x2
        class PE32(ctypes.Structure):
            _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
                        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
        k32 = ctypes.windll.kernel32
        def snap():
            h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if h == -1: return []
            out = []; pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
            if k32.Process32FirstW(h, ctypes.byref(pe)):
                while True:
                    out.append((int(pe.th32ProcessID), pe.szExeFile))
                    if not k32.Process32NextW(h, ctypes.byref(pe)): break
            k32.CloseHandle(ctypes.c_void_p(h))
            return out
        for pid, _ in snap(): seen.add(pid)
        while not stop.is_set():
            cur = snap()
            for pid, nm in cur:
                if pid not in seen:
                    seen.add(pid)
                    if nm.lower() in watch: emit("Proc", "Process", f"Start {nm}", pid=pid, level="MEDIUM")
            stop.wait(1.5)

def collector_etw(stop):
    provs = [("Kernel-Registry", "{70EB4F03-C1DE-4F73-A051-33D13D541355}"),
             ("Kernel-File", "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"),
             ("Shell-Core", "{30336ED4-E327-447C-9DE0-51B2E6059F02}"),
             ("Immersive-Shell", "{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}")]
    if not is_admin():
        STATUS.set("ETW", "red", "Admin gerekli")
        return
    
    if HAVE_ETW:
        try:
            pl = [etw_mod.ProviderInfo(n, etw_mod.GUID(g)) for n, g in provs]
            def cb(ev):
                try:
                    d = str(getattr(ev, "data", "")) or str(getattr(ev, "raw", ""))
                    if any(k in d.lower() for k in ("denied", "0x8007")):
                        emit("ETW", "Event", d, level="HIGH")
                    else:
                        emit("ETW", "Event", d, level="INFO")
                except: pass
            job = etw_mod.ETW(providers=pl, event_callback=cb)
            job.start()
            STATUS.set("ETW", "green", "pywintrace")
            while not stop.is_set(): stop.wait(1.0)
            job.stop()
            return
        except Exception as e:
            emit("ETW", "Error", f"pywintrace fail: {e}", level="LOW")

    tmp = tempfile.mkdtemp(prefix="bastard_")
    etl = os.path.join(tmp, "trace.etl"); csvp = os.path.join(tmp, "trace.csv"); pf = os.path.join(tmp, "provs.txt")
    try:
        with open(pf, "w") as f:
            for _, g in provs: f.write(f"{g} 0xffffffffffffffff 5\n")
        _run_silent(["logman", "stop", "BastardETW", "-ets"])
        r = _run_silent(["logman", "create", "trace", "BastardETW", "-ow", "-o", etl, "-pf", pf, "-ets"])
        if r.returncode == 0:
            STATUS.set("ETW", "yellow", "logman fallback")
            while not stop.is_set(): stop.wait(1.0)
            _run_silent(["logman", "stop", "BastardETW", "-ets"])
            if os.path.isfile(etl):
                _run_silent(["tracerpt", etl, "-of", "CSV", "-o", csvp, "-y"])
                if os.path.isfile(csvp):
                    with open(csvp, "r", encoding="utf-16", errors="replace") as f:
                        for row in csv.reader(f):
                            l = " | ".join(row)
                            if any(k in l.lower() for k in ("denied", "wallpaper", "photos", "transcoded")):
                                emit("ETW", "Event", l, level="MEDIUM")
            return
    except: pass
    STATUS.set("ETW", "red", "Tüm ETW yolları başarısız")

def collector_wmi(stop):
    if not HAVE_WMI: return STATUS.set("WMI", "red", "wmi yok")
    local_stop = threading.Event()
    def t_proc():
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI(); w = c.Win32_Process.watch_for("creation")
            while not (stop.is_set() or local_stop.is_set()):
                try:
                    p = w(timeout_ms=1000)
                    if p:
                        nm = (getattr(p, "Name", "") or "").lower()
                        cmd = (getattr(p, "CommandLine", "") or "").lower()
                        if nm in ("photos.exe", "runtimebroker.exe") or "wallpaper" in cmd:
                            emit("WMI", "Process", f"{nm} cmd={cmd}", pid=getattr(p, "ProcessId", 0), level="MEDIUM")
                except: local_stop.wait(0.5)
        except: pass
        finally: pythoncom.CoUninitialize()

    STATUS.set("WMI", "green", "active")
    t1 = threading.Thread(target=t_proc, daemon=True); t1.start()
    while not stop.is_set(): stop.wait(1.0)
    local_stop.set()

def collector_evtlog(stop):
    chans = ["Application", "System", "Microsoft-Windows-AppModel-Runtime/Admin"]
    STATUS.set("EvtLog", "green", "wevtutil")
    last_ts = time.time() - 30 
    while not stop.is_set():
        t0 = datetime.fromtimestamp(last_ts).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        now = time.time()
        for ch in chans:
            try:
                r = _run_silent(["wevtutil", "qe", ch, "/f:xml", "/rd:true", "/c:50", f"/q:*[System[TimeCreated[@SystemTime>='{t0}']]]"], capture_output=True)
                if r.returncode == 0:
                    txt = r.stdout.decode("utf-8", "replace")
                    for m in re.finditer(r"<Event\b.*?</Event>", txt, re.S):
                        frag = m.group(0)
                        if any(k in frag.lower() for k in ("error", "warning", "denied", "wallpaper", "photos")):
                            emit("EvtLog", "Log", f"{ch} {frag[:300]}...", level="MEDIUM")
            except: pass
        last_ts = now
        stop.wait(5.0)

class HookCollector:
    def __init__(self): self.win_hooks = []
    def install(self):
        try:
            user32 = ctypes.windll.user32
            WINEVENTPROC = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, wt.DWORD, wt.HWND, ctypes.c_long, ctypes.c_long, wt.DWORD, wt.DWORD)
            user32.SetWinEventHook.restype = ctypes.c_void_p
            def cb(hHook, event, hwnd, idObject, idChild, tid, evtTime):
                try:
                    cls = ctypes.create_unicode_buffer(256); ttl = ctypes.create_unicode_buffer(512)
                    user32.GetClassNameW(hwnd, cls, 256); user32.GetWindowTextW(hwnd, ttl, 512)
                    if "photos" in cls.value.lower() or "immersive" in cls.value.lower():
                        pid = wt.DWORD(); user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        emit("Hook", "Window", f"WinEvent {hex(event)} class={cls.value} title={ttl.value}", pid=pid.value)
                except: pass
            self.win_proc = WINEVENTPROC(cb)
            for ev in (0x8000, 0x8002):
                h = user32.SetWinEventHook(ev, ev, None, self.win_proc, 0, 0, 0x0000 | 0x0002)
                if h: self.win_hooks.append(h)
            if self.win_hooks: STATUS.set("Hook", "green", "winevent")
        except Exception as e: STATUS.set("Hook", "red", str(e))
    def uninstall(self):
        for h in self.win_hooks:
            try: ctypes.windll.user32.UnhookWinEvent(ctypes.c_void_p(h))
            except: pass

def run_all_probes():
    emit("Diag", "System", "=== Diagnostic Probes Started ===", level="INFO")
    
    pol = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallpaper"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreen"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "NoDispBackgroundPage")
    ]
    for rt, p, n in pol:
        v = reg_get(rt, p, n)
        if v and int(v) != 0: emit("Diag", "Policy", f"[FAIL] Policy block aktif: {p}\\{n}={v}", level="HIGH")
        else: emit("Diag", "Policy", f"[OK] {n} temiz", level="OK")

    try:
        any_found = False
        for b in [r"SystemFileAssociations\.jpg\shell\setaswallpaper", r"SystemFileAssociations\.png\shell\setaswallpaper"]:
            cmd = reg_get(winreg.HKEY_CLASSES_ROOT, f"{b}\\command", "")
            if cmd: any_found = True; emit("Diag", "Shell", f"[OK] {b} = {cmd}", level="OK")
        if not any_found: emit("Diag", "Shell", "[FAIL] Sağ tık Set As Desktop Background silinmiş!", level="HIGH")
    except: pass

    for cap in ["picturesLibrary", "userAccountInformation"]:
        v = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\" + cap, "Value")
        if str(v) == "Deny": emit("Diag", "Privacy", f"[FAIL] Consent {cap} = Deny", level="HIGH")
        else: emit("Diag", "Privacy", f"[OK] Consent {cap} = {v or 'unset'}", level="OK")

    try:
        r = _run_silent(["powershell", "-Command", "(Get-AppxPackage Microsoft.Windows.Photos).Capabilities | ForEach-Object { $_.Name }"], capture_output=True)
        if r.returncode == 0:
            caps = r.stdout.decode().strip().splitlines()
            if "picturesLibrary" not in caps: emit("Diag", "Appx", "[FAIL] Photos paketi picturesLibrary yetkisine sahip değil!", level="HIGH")
            else: emit("Diag", "Appx", "[OK] Photos yetkileri tam.", level="OK")
    except: pass

class T:
    BG       = "#11111b"
    PANEL    = "#181825"
    PANEL2   = "#1e1e2e"
    PANEL3   = "#313244"
    BORDER   = "#45475a"
    FG       = "#cdd6f4"
    FG_DIM   = "#a6adc8"
    ACCENT   = "#89b4fa"
    GREEN    = "#a6e3a1"
    YELLOW   = "#f9e2af"
    RED      = "#f38ba8"
    ORANGE   = "#fab387"
    PURPLE   = "#cba6f7"
    SELECT   = "#585b70"

class App(object):
    def __init__(self, root, admin_mode):
        self.root = root
        self.admin = admin_mode
        self.root.title(f"V3FINAL Forensic Diagnostic - {'[ADMIN]' if admin_mode else '[USER]'}")
        self.root.geometry("1400x900")
        self.root.configure(bg=T.BG)
        self.stop_flag = StopFlag()
        self.collectors = []
        self.hook = None
        self.events = []
        
        self.f_src = {s: tk.BooleanVar(value=True) for s in ["Diag", "RegPoll", "FileWatch", "Proc", "ETW", "WMI", "EvtLog", "Hook", "WinRT"]}
        self.f_err = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        
        self._setup_theme()
        self._build_ui()
        self._pump()
        self._status_pump()

    def _setup_theme(self):
        s = ttk.Style()
        try: s.theme_use("clam")
        except: pass
        s.configure(".", background=T.BG, foreground=T.FG, fieldbackground=T.PANEL2, bordercolor=T.BORDER)
        s.configure("TButton", background=T.PANEL3, foreground=T.FG, padding=6, borderwidth=0)
        s.map("TButton", background=[("active", T.SELECT), ("disabled", T.PANEL)])
        s.configure("Accent.TButton", background=T.ACCENT, foreground=T.BG, font=("Segoe UI", 9, "bold"))
        s.configure("Danger.TButton", background=T.RED, foreground=T.BG, font=("Segoe UI", 9, "bold"))
        s.configure("Treeview", background=T.PANEL, foreground=T.FG, fieldbackground=T.PANEL, rowheight=24, borderwidth=0, font=("Consolas", 9))
        s.map("Treeview", background=[("selected", T.SELECT)], foreground=[("selected", T.FG)])
        s.configure("Treeview.Heading", background=T.PANEL2, foreground=T.FG, font=("Segoe UI", 9, "bold"), borderwidth=0)

    def _build_ui(self):
        tb = tk.Frame(self.root, bg=T.PANEL2, padx=10, pady=10)
        tb.pack(side="top", fill="x")
        self.btn_start = ttk.Button(tb, text="▶ START TRACE", style="Accent.TButton", command=self.on_start)
        self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(tb, text="⏹ STOP", style="Danger.TButton", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        self.btn_mark = ttk.Button(tb, text="📌 MARKER", command=lambda: emit("System", "Marker", ">>> USER MARKER <<<", level="HIGH"))
        self.btn_mark.pack(side="left", padx=5)
        
        ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(tb, text="Run Probes", command=lambda: threading.Thread(target=run_all_probes, daemon=True).start()).pack(side="left", padx=2)
        ttk.Button(tb, text="Shell Restore", command=self.action_shell_restore).pack(side="left", padx=2)
        ttk.Button(tb, text="Photos ReReg", command=self.action_photos_rereg).pack(side="left", padx=2)
        ttk.Button(tb, text="SPI API Test", command=self.action_spi_test).pack(side="left", padx=2)
        ttk.Button(tb, text="Save CSV", command=self.action_save_csv).pack(side="right", padx=5)

        body = tk.Frame(self.root, bg=T.BG)
        body.pack(side="top", fill="both", expand=True)

        left = tk.Frame(body, bg=T.PANEL, width=200)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="MODULE STATUS", bg=T.PANEL, fg=T.FG_DIM, font=("Segoe UI", 10, "bold")).pack(pady=10)
        
        self.leds = {}
        for src in self.f_src.keys():
            fr = tk.Frame(left, bg=T.PANEL)
            fr.pack(fill="x", padx=10, pady=2)
            cv = tk.Canvas(fr, width=12, height=12, bg=T.PANEL, highlightthickness=0)
            cv.pack(side="left", pady=2)
            dot = cv.create_oval(1, 1, 11, 11, fill=T.SELECT, outline="")
            lbl = tk.Label(fr, text=src, bg=T.PANEL, fg=T.FG, font=("Segoe UI", 9))
            lbl.pack(side="left", padx=5)
            self.leds[src] = (cv, dot, lbl)

        right = tk.Frame(body, bg=T.BG)
        right.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        ff = tk.Frame(right, bg=T.BG)
        ff.pack(fill="x", pady=(0, 10))
        for k, v in self.f_src.items():
            cb = tk.Checkbutton(ff, text=k, variable=v, bg=T.BG, fg=T.FG_DIM, selectcolor=T.PANEL2, command=self.refresh_tree)
            cb.pack(side="left")
        tk.Checkbutton(ff, text="Err Only", variable=self.f_err, bg=T.BG, fg=T.RED, selectcolor=T.PANEL2, command=self.refresh_tree).pack(side="left", padx=10)
        tk.Entry(ff, textvariable=self.search_var, bg=T.PANEL2, fg=T.FG, insertbackground=T.FG).pack(side="right")
        self.search_var.trace_add("write", lambda *a: self.refresh_tree())
        tk.Label(ff, text="Search:", bg=T.BG, fg=T.FG).pack(side="right", padx=5)

        pw = ttk.PanedWindow(right, orient="vertical")
        pw.pack(fill="both", expand=True)

        tf = tk.Frame(pw, bg=T.BG)
        pw.add(tf, weight=3)
        cols = ("Time", "Source", "Type", "PID", "Level", "Detail")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for w, c in zip([100, 90, 90, 60, 70, 800], cols):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        
        ysb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        
        self.tree.tag_configure("HIGH", foreground=T.RED)
        self.tree.tag_configure("MEDIUM", foreground=T.ORANGE)
        self.tree.tag_configure("OK", foreground=T.GREEN)
        self.tree.tag_configure("INFO", foreground=T.FG)
        
        self.tree.tag_configure("odd", background=T.PANEL2)
        self.tree.tag_configure("even", background=T.PANEL)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        df = tk.Frame(pw, bg=T.BG)
        pw.add(df, weight=1)
        tk.Label(df, text="Event Details (Master-Detail View)", bg=T.BG, fg=T.ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.detail_txt = scrolledtext.ScrolledText(df, bg=T.PANEL, fg=T.FG, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.detail_txt.pack(fill="both", expand=True, pady=5)

        self.sb = tk.Label(self.root, text="Ready", bg=T.PANEL3, fg=T.FG, anchor="w", padx=10)
        self.sb.pack(side="bottom", fill="x")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        val = item["values"]
        if not val: return
        text = f"[{val[0]}] {val[1]} | {val[2]} | PID: {val[3]} | Level: {val[4]}\n\n{val[5]}"
        self.detail_txt.config(state="normal")
        self.detail_txt.delete("1.0", "end")
        self.detail_txt.insert("end", text)
        self.detail_txt.config(state="disabled")

    def _status_pump(self):
        st = STATUS.get()
        for src, (cv, dot, lbl) in self.leds.items():
            state, note = st.get(src, ("gray", ""))
            color = {"green": T.GREEN, "yellow": T.YELLOW, "red": T.RED}.get(state, T.SELECT)
            cv.itemconfig(dot, fill=color)
            lbl.config(text=f"{src} ({state})")
        self.sb.config(text=f"Events: {len(self.events)} | Queue: {BUS.q.qsize()} | Dropped: {BUS.dropped}")
        self.root.after(1000, self._status_pump)

    def _pump(self):
        evs = BUS.drain()
        if evs:
            for e in evs:
                self.events.append(e)
                if self._passes(e):
                    tags = (e.level, "even" if len(self.tree.get_children()) % 2 == 0 else "odd")
                    self.tree.insert("", "end", values=(e.fmt_time(), e.source, e.type, e.pid, e.level, e.detail), tags=tags)
            if self.tree.get_children():
                self.tree.see(self.tree.get_children()[-1])
        self.root.after(100, self._pump)

    def _passes(self, e):
        if not self.f_src.get(e.source, tk.BooleanVar(value=True)).get(): return False
        if self.f_err.get() and e.level not in ("HIGH", "MEDIUM"): return False
        q = self.search_var.get().lower()
        if q and q not in e.detail.lower(): return False
        return True

    def refresh_tree(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for i, e in enumerate(self.events):
            if self._passes(e):
                tags = (e.level, "even" if i % 2 == 0 else "odd")
                self.tree.insert("", "end", values=(e.fmt_time(), e.source, e.type, e.pid, e.level, e.detail), tags=tags)

    def on_start(self):
        self.stop_flag.evt.clear()
        self.events.clear(); self.refresh_tree()
        emit("System", "Control", f"Trace Started. Admin={self.admin}", level="INFO")
        
        self.hook = HookCollector(); self.hook.install()
        
        def spawn(fn):
            t = threading.Thread(target=fn, args=(self.stop_flag,), daemon=True); t.start()
            return t
        
        self.collectors = [
            spawn(collector_regpoll), spawn(collector_filewatch),
            spawn(collector_proc), spawn(collector_wmi),
            spawn(collector_etw), spawn(collector_evtlog)
        ]
        threading.Thread(target=run_all_probes, daemon=True).start()
        
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

    def on_stop(self):
        emit("System", "Control", "Trace Stopping...", level="INFO")
        self.stop_flag.set()
        if self.hook: self.hook.uninstall()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")

    def action_shell_restore(self):
        if not messagebox.askyesno("Shell Restore", "HKCU altına setaswallpaper verb'ü geri yüklensin mi?"): return
        try:
            b = r"Software\Classes\SystemFileAssociations\.jpg\shell\setaswallpaper"
            k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, b, 0, winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(k, None, 0, winreg.REG_SZ, "Set as desktop background")
            winreg.CloseKey(k)
            ck = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, b + r"\command", 0, winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(ck, None, 0, winreg.REG_SZ, r'rundll32.exe "%SystemRoot%\System32\shell32.dll",SetWallpaperFromPicture %1')
            winreg.CloseKey(ck)
            emit("Diag", "Shell", "Shell verb başarıyla yüklendi.", level="OK")
        except Exception as e:
            emit("Diag", "Shell", f"Shell restore hatası: {e}", level="HIGH")

    def action_photos_rereg(self):
        def _r():
            r = _run_silent(["powershell", "-Command", "Get-AppxPackage Microsoft.Windows.Photos | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\\AppXManifest.xml\"}"], capture_output=True)
            if r.returncode == 0: emit("Diag", "Appx", "Photos Re-register başarılı.", level="OK")
            else: emit("Diag", "Appx", f"Photos Re-register HATA: {r.stderr.decode()[:200]}", level="HIGH")
        threading.Thread(target=_r, daemon=True).start()

    def action_spi_test(self):
        p = filedialog.askopenfilename(title="Wallpaper Resmi Seç", filetypes=[("Images", "*.jpg *.png *.bmp")])
        if not p: return
        def _r():
            ok = ctypes.windll.user32.SystemParametersInfoW(20, 0, p, 1 | 2)
            if ok: emit("Diag", "API", "SPI_SETDESKWALLPAPER Başarılı. API sağlam.", level="OK")
            else: emit("Diag", "API", f"SPI HATA: {ctypes.get_last_error()}", level="HIGH")
        threading.Thread(target=_r, daemon=True).start()

    def action_save_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not p: return
        try:
            with open(p, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Time", "Source", "Type", "PID", "Level", "Detail"])
                for e in self.events: w.writerow([e.fmt_time(), e.source, e.type, e.pid, e.level, e.detail])
            messagebox.showinfo("Kayıt", "CSV başarıyla kaydedildi.")
        except Exception as e: messagebox.showerror("Hata", str(e))

    def on_close(self):
        self.stop_flag.set()
        if self.hook: self.hook.uninstall()
        self.root.destroy()

def main():
    admin = is_admin()
    if not admin:
        root = tk.Tk(); root.withdraw()
        res = messagebox.askyesnocancel("Yönetici İzni", "ETW (Kernel Trace) için yönetici izni önerilir.\n\nYes = Yönetici olarak başlat\nNo = Sınırlı modda devam et")
        root.destroy()
        if res is None: return
        if res:
            if relaunch_as_admin(): return
            messagebox.showwarning("Hata", "Yönetici isteği reddedildi, normal devam ediliyor.")
    
    root = tk.Tk()
    app = App(root, admin)
    root.mainloop()

if __name__ == "__main__":
    main()