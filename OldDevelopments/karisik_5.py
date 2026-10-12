#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 28.pyw - Windows forensic diagnostic tool (single file, ASCII only)
#
# CHANGELOG (28):
# - WPR status: "not needed (pywintrace)" / "not needed (logman)"
#   instead of "not used". Clearer when ETW path is active.
# - Hook status: green when any hook works (cwpret or winevent).
#   Note shows which method is active: "ok", "winevent", "cwpret".
# - Events tree: vertical AND horizontal scrollbars, both visible
#   against dark theme. Grid layout inside the container so long
#   detail rows can be inspected without cutting off.
# - Scrollbar styles: lighter thumb (PANEL3), visible arrow color.

import os, sys, time, json, csv, re, threading, queue, traceback
import subprocess, tempfile, ctypes
import ctypes.wintypes as wt
from datetime import datetime, timezone
from collections import deque

try:
    import winreg
except Exception:
    winreg = None

# ---------------------------------------------------------------------------
# Hidden subprocess runner
# ---------------------------------------------------------------------------
CREATE_NO_WINDOW = 0x08000000

def _run(cmd, timeout=30, **kw):
    if os.name == "nt":
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            kw.setdefault("startupinfo", si)
            kw.setdefault("creationflags", CREATE_NO_WINDOW)
        except Exception:
            pass
    return subprocess.run(cmd, timeout=timeout, **kw)

# ---------------------------------------------------------------------------
# Desktop
# ---------------------------------------------------------------------------
def _resolve_desktop():
    try:
        CSIDL_DESKTOPDIRECTORY = 0x0010
        buf = ctypes.create_unicode_buffer(260)
        r = ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOPDIRECTORY,
                                                   None, 0, buf)
        if r == 0 and buf.value and os.path.isdir(buf.value):
            return buf.value
    except Exception:
        pass
    try:
        if winreg:
            for kp in (
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"):
                try:
                    h = winreg.OpenKey(winreg.HKEY_CURRENT_USER, kp)
                    try:
                        v, _ = winreg.QueryValueEx(h, "Desktop")
                    finally:
                        winreg.CloseKey(h)
                    v = os.path.expandvars(v)
                    if os.path.isdir(v):
                        return v
                except Exception:
                    pass
    except Exception:
        pass
    up = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    d = os.path.join(up, "Desktop")
    if os.path.isdir(d):
        return d
    return up

HOME = os.path.expanduser("~")
DESKTOP = _resolve_desktop()

TAG = "28"
STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LIVE_LOG_PATH = os.path.join(DESKTOP, TAG + "_" + STAMP + ".log")
STARTUP_LOG_PATH = os.path.join(DESKTOP, TAG + "_startup.log")

_log_lock = threading.Lock()

def _write(path, line):
    with _log_lock:
        for _ in range(3):
            try:
                with open(path, "a", encoding="utf-8", errors="replace") as f:
                    f.write(line if line.endswith("\n") else line + "\n")
                    f.flush()
                    try: os.fsync(f.fileno())
                    except Exception: pass
                return True
            except Exception:
                try: os.makedirs(os.path.dirname(path), exist_ok=True)
                except Exception: pass
                time.sleep(0.05)
    return False

def startup_log(msg):
    _write(STARTUP_LOG_PATH,
           "[" + datetime.now().strftime("%H:%M:%S.%f")[:-3] + "] " + str(msg))

def live_log(msg):
    _write(LIVE_LOG_PATH,
           "[" + datetime.now().strftime("%H:%M:%S.%f")[:-3] + "] " + str(msg))

def _init_log_files():
    for p, title in ((LIVE_LOG_PATH, "live events"),
                     (STARTUP_LOG_PATH, "startup")):
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write("Fsniff " + TAG + " - " + title + "\n")
                f.write("started " + datetime.now().isoformat() + "\n")
                f.write("pid " + str(os.getpid()) + "\n")
                f.write("desktop " + DESKTOP + "\n")
        except Exception:
            pass
_init_log_files()
startup_log("=== " + TAG + ".pyw starting pid=" + str(os.getpid()) + " ===")
startup_log("desktop = " + DESKTOP)

def _excepthook(et, e, tb):
    txt = "".join(traceback.format_exception(et, e, tb))
    startup_log("UNCAUGHT: " + txt)
    live_log("[FATAL] uncaught:\n" + txt)
sys.excepthook = _excepthook

def _threadhook(args):
    txt = "".join(traceback.format_exception(args.exc_type, args.exc_value,
                                              args.exc_traceback))
    startup_log("THREAD " + getattr(args.thread, "name", "?") + ": " + txt)
    live_log("[FATAL] thread " + getattr(args.thread, "name", "?") + ":\n" + txt)
try:
    threading.excepthook = _threadhook
except Exception:
    pass

# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------
class UEvent(object):
    __slots__ = ("ts", "source", "type", "pid", "detail", "level")
    def __init__(self, ts, source, type_, pid, detail, level="INFO"):
        self.ts = ts
        self.source = source
        self.type = type_
        self.pid = pid
        self.detail = detail
        self.level = level
    def fmt_time(self):
        return datetime.fromtimestamp(self.ts).strftime("%H:%M:%S.%f")[:-3]

ALL_SOURCES = ["System", "Diag", "ProcMon", "ETW", "WPR", "WMI", "RegPoll",
               "FileWatch", "Hook", "Win32", "EvtLog", "Proc", "WinRT"]
ALL_TYPES = ["System", "Diag", "Registry", "File", "Process", "Window",
             "Event", "Error", "Marker", "Network"]

class EventBus(object):
    def __init__(self, maxlen=2000):
        self.q = queue.Queue()
        self.maxlen = maxlen
        self.dropped = 0
        self.lock = threading.Lock()
        self._size = 0
        self.history = deque(maxlen=50000)
        self.hist_lock = threading.Lock()
    def put(self, ev):
        with self.hist_lock:
            self.history.append(ev)
        with self.lock:
            if self._size >= self.maxlen:
                try:
                    self.q.get_nowait(); self._size -= 1; self.dropped += 1
                except queue.Empty:
                    pass
            try:
                self.q.put_nowait(ev); self._size += 1
            except Exception:
                pass
    def drain(self, maxn=500):
        out = []
        for _ in range(maxn):
            try:
                out.append(self.q.get_nowait())
                with self.lock:
                    self._size = max(0, self._size - 1)
            except queue.Empty:
                break
        return out

BUS = EventBus()

class SourceStatus(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}
    def set(self, name, state, note=""):
        with self.lock:
            self.data[name] = (state, note)
        live_log("[status] " + name + " = " + state + " " + note)
    def get(self, name):
        with self.lock:
            return self.data.get(name, ("gray", ""))
    def all(self):
        with self.lock:
            return dict(self.data)

STATUS = SourceStatus()

def emit(source, type_, pid, detail, level="INFO"):
    ev = UEvent(time.time(), source, type_, pid, detail, level)
    BUS.put(ev)
    live_log("[" + level + "] " + source + "/" + type_ + " " + str(detail)[:400])
    return ev

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_as_admin():
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join('"%s"' % a for a in sys.argv[1:])
        exe = sys.executable
        if exe.lower().endswith("python.exe"):
            cand = exe[:-10] + "pythonw.exe"
            if os.path.isfile(cand):
                exe = cand
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe,
            '"%s" %s' % (script, params), None, 1)
        return int(r) > 32
    except Exception as e:
        startup_log("relaunch failed: " + str(e))
        return False

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
NONPRINT_THRESHOLD = 0.30
BLOB_MAX_LEN = 200

def _safe_val(val, typ):
    try:
        if winreg and typ == winreg.REG_BINARY:
            if val is None:
                return "<binary 0 bytes>"
            n = len(val)
            nonp = sum(1 for b in val if not (32 <= b < 127))
            ratio = (nonp / n) if n else 0.0
            if ratio > NONPRINT_THRESHOLD or n > 64:
                return "<binary %d bytes>" % n
            return "0x" + val.hex()
        s = str(val)
        if len(s) > BLOB_MAX_LEN:
            s = s[:BLOB_MAX_LEN] + "...(%d)" % len(s)
        return s
    except Exception:
        return "<unprintable>"

def _reg_enum_tree(root, subkey, max_depth=6, _depth=0):
    if winreg is None or _depth > max_depth:
        return {}
    out = {}
    try:
        h = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
    except Exception:
        return {}
    try:
        n_sub, n_val, _ = winreg.QueryInfoKey(h)
        for i in range(n_val):
            try:
                name, val, typ = winreg.EnumValue(h, i)
                out["v:" + name] = _safe_val(val, typ)
            except Exception:
                pass
        for i in range(n_sub):
            try:
                sn = winreg.EnumKey(h, i)
                child = _reg_enum_tree(root, subkey + "\\" + sn, max_depth, _depth + 1)
                for k, v in child.items():
                    out[sn + "\\" + k] = v
            except Exception:
                pass
    finally:
        try: winreg.CloseKey(h)
        except Exception: pass
    return out

def reg_get(root, path, name):
    if winreg is None:
        return None
    try:
        h = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        try:
            v, _ = winreg.QueryValueEx(h, name)
            return v
        finally:
            winreg.CloseKey(h)
    except Exception:
        return None

def reg_key_exists(root, path):
    if winreg is None:
        return False
    try:
        h = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        winreg.CloseKey(h)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Stop flag
# ---------------------------------------------------------------------------
class StopFlag(object):
    def __init__(self):
        self.evt = threading.Event()
    def set(self):
        self.evt.set()
    def is_set(self):
        return self.evt.is_set()
    def wait(self, t):
        return self.evt.wait(t)

# ---------------------------------------------------------------------------
# RegPoll
# ---------------------------------------------------------------------------
REG_ROOTS = [
    ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None,
     r"Control Panel\Desktop"),
    ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers"),
    ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\Lock Screen"),
    ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\Themes"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"),
]

def collector_regpoll(stop):
    if winreg is None:
        STATUS.set("RegPoll", "red", "winreg yok")
        return
    STATUS.set("RegPoll", "gray", "snapshot")
    prev = {}
    for tag, root, path in REG_ROOTS:
        prev[(tag, path)] = _reg_enum_tree(root, path)
    STATUS.set("RegPoll", "green", "polling 1s")
    while not stop.is_set():
        try:
            for tag, root, path in REG_ROOTS:
                cur = _reg_enum_tree(root, path)
                old = prev.get((tag, path), {})
                for k, v in cur.items():
                    if old.get(k, "__MISSING__") != v:
                        if k.startswith("v:"):
                            name = k[2:]
                            if name == "TranscodedImageCache":
                                continue
                            oldv = old.get(k, "<yok>")
                            emit("RegPoll", "Registry", 0,
                                 "%s\\%s [%s]: %s -> %s" %
                                 (tag, path, name, oldv, v),
                                 "MEDIUM" if "wallpaper" in path.lower() else "INFO")
                        else:
                            emit("RegPoll", "Registry", 0,
                                 "%s\\%s [%s] created = %s" % (tag, path, k, v),
                                 "INFO")
                for k, v in old.items():
                    if k not in cur:
                        emit("RegPoll", "Registry", 0,
                             "%s\\%s [%s] deleted (was %s)" %
                             (tag, path, k[2:] if k.startswith("v:") else k, v),
                             "MEDIUM")
                prev[(tag, path)] = cur
        except Exception as e:
            emit("RegPoll", "Error", 0, "poll: " + str(e), "MEDIUM")
        stop.wait(1.0)

# ---------------------------------------------------------------------------
# FileWatch
# ---------------------------------------------------------------------------
FW_DIRS = [
    os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Themes"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\Themes"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""),
                 r"Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe"),
    os.path.join(os.environ.get("APPDATA", ""),
                 r"Microsoft\Windows\Themes\CachedFiles"),
]

def _dir_snapshot(d):
    out = {}
    try:
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                st = os.stat(p)
                out[name] = (st.st_size, int(st.st_mtime))
            except Exception:
                out[name] = (0, 0)
    except Exception:
        pass
    return out

def collector_filewatch(stop):
    try:
        import watchdog  # noqa
        have_wd = True
    except Exception:
        have_wd = False
    dirs = [d for d in FW_DIRS if d and os.path.isdir(d)]
    if not dirs:
        STATUS.set("FileWatch", "red", "klasor yok")
        return
    if not have_wd:
        prev = {d: _dir_snapshot(d) for d in dirs}
        STATUS.set("FileWatch", "green", "poll %d dirs" % len(dirs))
        while not stop.is_set():
            try:
                for d in dirs:
                    cur = _dir_snapshot(d)
                    old = prev.get(d, {})
                    for k, v in cur.items():
                        if k not in old:
                            emit("FileWatch", "File", 0,
                                 "created %s\\%s (%d bytes)" % (d, k, v[0]),
                                 "MEDIUM")
                        elif old[k] != v:
                            emit("FileWatch", "File", 0,
                                 "modified %s\\%s" % (d, k), "MEDIUM")
                    for k in old:
                        if k not in cur:
                            emit("FileWatch", "File", 0,
                                 "deleted %s\\%s" % (d, k), "MEDIUM")
                    prev[d] = cur
            except Exception as e:
                emit("FileWatch", "Error", 0, str(e), "MEDIUM")
            stop.wait(1.0)
        return
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        class H(FileSystemEventHandler):
            def on_any_event(self, event):
                try:
                    emit("FileWatch", "File", 0,
                         "%s %s" % (event.event_type, event.src_path), "MEDIUM")
                except Exception:
                    pass
        obs = Observer()
        h = H()
        for d in dirs:
            try: obs.schedule(h, d, recursive=True)
            except Exception: pass
        obs.start()
        STATUS.set("FileWatch", "green", "watchdog %d" % len(dirs))
        while not stop.is_set():
            stop.wait(1.0)
        try: obs.stop(); obs.join(timeout=3)
        except Exception: pass
    except Exception as e:
        STATUS.set("FileWatch", "red", "watchdog: " + str(e))

# ---------------------------------------------------------------------------
# Win32
# ---------------------------------------------------------------------------
SPI_GETDESKWALLPAPER = 0x0073
SPI_SETDESKWALLPAPER = 0x0014
SPIF_UPDATEINIFILE = 0x01
SPIF_SENDCHANGE = 0x02

def win32_get_wallpaper():
    buf = ctypes.create_unicode_buffer(512)
    try:
        ok = ctypes.windll.user32.SystemParametersInfoW(SPI_GETDESKWALLPAPER,
                                                        512, buf, 0)
        if ok:
            return buf.value
    except Exception:
        pass
    return ""

def win32_set_wallpaper(path):
    try:
        ok = ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 0, path,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
        err = ctypes.get_last_error() if not ok else 0
        return bool(ok), err
    except Exception as e:
        return False, str(e)

def collector_win32(stop):
    STATUS.set("Win32", "gray", "probe")
    wp = win32_get_wallpaper()
    emit("Win32", "Event", 0, "SPI_GETDESKWALLPAPER = " + (wp or "<bos>"),
         "INFO" if wp else "MEDIUM")
    emit("Win32", "Event", 0, "IsUserAnAdmin = " + str(is_admin()), "INFO")
    STATUS.set("Win32", "green", "polling 5s")
    last = wp
    while not stop.is_set():
        stop.wait(5.0)
        try:
            cur = win32_get_wallpaper()
            if cur != last:
                emit("Win32", "Registry", 0,
                     "wallpaper degisti: %s -> %s" % (last, cur), "MEDIUM")
                last = cur
        except Exception as e:
            emit("Win32", "Error", 0, str(e), "LOW")

# ---------------------------------------------------------------------------
# Proc
# ---------------------------------------------------------------------------
WATCH_PROCS = {
    "photos.exe", "runtimebroker.exe", "dllhost.exe", "systemsettings.exe",
    "explorer.exe", "sihost.exe", "startmenuexperiencehost.exe",
    "searchhost.exe", "backgroundtaskhost.exe", "applicationframehost.exe",
    "lockapp.exe",
}

def collector_proc(stop):
    try:
        import psutil  # noqa
        use_psutil = True
    except Exception:
        use_psutil = False
    STATUS.set("Proc", "gray", "init")
    seen = set()
    if use_psutil:
        import psutil
        STATUS.set("Proc", "green", "psutil")
        try:
            for p in psutil.process_iter(["pid"]):
                try: seen.add(p.info["pid"])
                except Exception: pass
        except Exception:
            pass
        while not stop.is_set():
            try:
                for p in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        pid = p.info["pid"]
                        if pid in seen:
                            continue
                        seen.add(pid)
                        nm = (p.info["name"] or "").lower()
                        cmd = " ".join(p.info["cmdline"] or [])
                        interesting = nm in WATCH_PROCS or any(
                            k in cmd.lower() for k in
                            ("wallpaper", "theme", "photos", "lockscreen"))
                        if interesting:
                            emit("Proc", "Process", pid,
                                 "start %s cmd=%s" % (nm, cmd[:300]), "MEDIUM")
                    except Exception:
                        pass
                cur = set()
                for p in psutil.process_iter(["pid"]):
                    try: cur.add(p.info["pid"])
                    except Exception: pass
                for pid in list(seen):
                    if pid not in cur:
                        seen.discard(pid)
            except Exception as e:
                emit("Proc", "Error", 0, "psutil: " + str(e), "LOW")
            stop.wait(1.5)
        return
    STATUS.set("Proc", "green", "Toolhelp32")
    TH32CS_SNAPPROCESS = 0x2
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]
    k32 = ctypes.windll.kernel32
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
    k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
    def snap():
        h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not h or h == ctypes.c_void_p(-1).value:
            return []
        out = []
        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if k32.Process32FirstW(h, ctypes.byref(pe)):
                while True:
                    out.append((int(pe.th32ProcessID), pe.szExeFile))
                    if not k32.Process32NextW(h, ctypes.byref(pe)):
                        break
        finally:
            try: k32.CloseHandle(ctypes.c_void_p(h))
            except Exception: pass
        return out
    for pid, nm in snap():
        seen.add(pid)
    while not stop.is_set():
        try:
            cur = snap()
            cur_ids = set(p for p, _ in cur)
            for pid, nm in cur:
                if pid not in seen and nm.lower() in WATCH_PROCS:
                    emit("Proc", "Process", pid, "start " + nm, "MEDIUM")
                seen.add(pid)
            for pid in list(seen):
                if pid not in cur_ids:
                    seen.discard(pid)
        except Exception as e:
            emit("Proc", "Error", 0, "snap: " + str(e), "LOW")
        stop.wait(1.5)

# ---------------------------------------------------------------------------
# EvtLog
# ---------------------------------------------------------------------------
EVT_CHANNELS = [
    "Application",
    "System",
    "Microsoft-Windows-AppModel-Runtime/Admin",
    "Microsoft-Windows-Shell-Core/Operational",
    "Microsoft-Windows-AppXDeployment/Operational",
    "Microsoft-Windows-TWinUI/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
]

def collector_evtlog(stop):
    try:
        import win32evtlog  # noqa
    except Exception:
        STATUS.set("EvtLog", "red", "pywin32 yok")
        return
    since = time.time() - 60
    STATUS.set("EvtLog", "gray", "backfill 60s")
    def _backfill():
        t0 = datetime.fromtimestamp(since).astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        for ch in EVT_CHANNELS:
            try:
                cmd = ["wevtutil", "qe", ch, "/f:xml", "/rd:true", "/c:250",
                       "/q:*[System[TimeCreated[@SystemTime>='" + t0 + "']]]"]
                r = _run(cmd, capture_output=True, timeout=30)
                if r.returncode != 0:
                    continue
                txt = r.stdout.decode("utf-8", "replace")
                for m in re.finditer(r"<Event\b.*?</Event>", txt, re.S):
                    frag = m.group(0)
                    lvl = re.search(r"<Level>(\d+)</Level>", frag)
                    lv = int(lvl.group(1)) if lvl else 4
                    sev = {1: "HIGH", 2: "HIGH", 3: "MEDIUM", 4: "INFO"}.get(lv, "INFO")
                    emit("EvtLog", "Event", 0,
                         "%s lvl=%d %s" % (ch, lv, frag[:200].replace("\n", " ")),
                         sev)
            except Exception as e:
                emit("EvtLog", "Error", 0, "backfill %s: %s" % (ch, e), "LOW")
    _backfill()
    STATUS.set("EvtLog", "green", "polling 5s")
    last_ts = time.time()
    while not stop.is_set():
        stop.wait(5.0)
        now = time.time()
        t0 = datetime.fromtimestamp(last_ts).astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        for ch in EVT_CHANNELS:
            try:
                cmd = ["wevtutil", "qe", ch, "/f:xml", "/rd:true", "/c:100",
                       "/q:*[System[TimeCreated[@SystemTime>='" + t0 + "']]]"]
                r = _run(cmd, capture_output=True, timeout=15)
                if r.returncode != 0:
                    continue
                txt = r.stdout.decode("utf-8", "replace")
                for m in re.finditer(r"<Event\b.*?</Event>", txt, re.S):
                    emit("EvtLog", "Event", 0,
                         "%s %s" % (ch, m.group(0)[:200].replace("\n", " ")),
                         "MEDIUM")
            except Exception:
                pass
        last_ts = now

# ---------------------------------------------------------------------------
# WMI
# ---------------------------------------------------------------------------
def collector_wmi(stop):
    try:
        import pythoncom  # noqa
        import wmi  # noqa
    except Exception:
        STATUS.set("WMI", "red", "wmi/pythoncom yok")
        return
    import pythoncom, wmi
    STATUS.set("WMI", "gray", "init")
    stop_local = threading.Event()
    def t_proc():
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            w = c.Win32_Process.watch_for("creation")
            STATUS.set("WMI", "green", "process watcher")
            while not (stop.is_set() or stop_local.is_set()):
                try:
                    p = w(timeout_ms=1000)
                    if p:
                        emit("WMI", "Process", getattr(p, "ProcessId", 0),
                             "Win32_Process %s cmd=%s" %
                             ((getattr(p, "Name", "") or "").lower(),
                              (getattr(p, "CommandLine", "") or "")[:200]),
                             "MEDIUM")
                except Exception:
                    stop_local.wait(0.5)
        except Exception as e:
            STATUS.set("WMI", "red", "proc: " + str(e))
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass
    def t_reg():
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            targets = [
                ("HKEY_CURRENT_USER", r"Control Panel\Desktop", "WallPaper"),
                ("HKEY_CURRENT_USER", r"Control Panel\Desktop", "WallpaperStyle"),
                ("HKEY_CURRENT_USER",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
                 "BackgroundType"),
            ]
            watchers = []
            for hive, kp, vn in targets:
                try:
                    w = c.RegistryValueChangeEvent.watch_for(
                        Hive=hive, KeyPath=kp, ValueName=vn)
                    watchers.append((w, hive, kp, vn))
                except Exception:
                    pass
            if not watchers:
                emit("WMI", "Error", 0,
                     "RegistryValueChangeEvent kurulamadi, RegPoll devrede",
                     "LOW")
                return
            while not (stop.is_set() or stop_local.is_set()):
                for w, hive, kp, vn in watchers:
                    try:
                        ev = w(timeout_ms=500)
                        if ev:
                            emit("WMI", "Registry", 0,
                                 "%s\\%s\\%s = %s" % (hive, kp, vn,
                                 getattr(ev, "NewValue", "?")), "MEDIUM")
                    except Exception:
                        pass
        except Exception as e:
            emit("WMI", "Error", 0, "reg: " + str(e), "LOW")
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass
    th1 = threading.Thread(target=t_proc, name="wmi-proc", daemon=True)
    th2 = threading.Thread(target=t_reg, name="wmi-reg", daemon=True)
    th1.start(); th2.start()
    while not stop.is_set():
        stop.wait(1.0)
    stop_local.set()
    th1.join(timeout=3); th2.join(timeout=3)

# ---------------------------------------------------------------------------
# ETW / WPR
# ---------------------------------------------------------------------------
ETW_PROVIDERS = [
    ("Kernel-Registry", "{70EB4F03-C1DE-4F73-A051-33D13D541355}"),
    ("Kernel-File", "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"),
    ("Shell-Core", {30336ED4-E327-447C-9DE0-51B2E6059F02}"),
    ("Immersive-Shell", "{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}"),
]

def _try_pywintrace(stop):
    try:
        import etw  # noqa
    except Exception:
        return False
    try:
        import etw
        PROVIDERS = []
        for name, guid in ETW_PROVIDERS:
            try:
                PROVIDERS.append(etw.ProviderInfo(name, etw.GUID(guid)))
            except Exception:
                pass
        if not PROVIDERS:
            return False
        def cb(event):
            try:
                data = str(getattr(event, "data", "")) or str(getattr(event, "raw", ""))
                emit("ETW", "Event", 0, data[:400], "INFO")
            except Exception:
                pass
        job = etw.ETW(providers=PROVIDERS, event_callback=cb)
        job.start()
        STATUS.set("ETW", "green", "pywintrace")
        STATUS.set("WPR", "gray", "not needed (pywintrace)")
        while not stop.is_set():
            stop.wait(1.0)
        try: job.stop()
        except Exception: pass
        return True
    except Exception as e:
        emit("ETW", "Error", 0, "pywintrace: " + str(e), "LOW")
        return False

def _parse_tracerpt_csv(path):
    try:
        enc = "utf-16"
        try:
            with open(path, "rb") as f:
                head = f.read(2)
            if head[:2] not in (b"\xff\xfe", b"\xfe\xff"):
                enc = "utf-8"
        except Exception:
            pass
        with open(path, "r", encoding=enc, errors="replace") as f:
            rd = csv.reader(f, delimiter=",")
            for i, row in enumerate(rd):
                if i == 0:
                    continue
                line = " | ".join(c for c in row if c)
                if not line.strip():
                    continue
                low = line.lower()
                if ("denied" in low or "0x800" in low or "wallpaper" in low
                        or "photos" in low or "transcoded" in low
                        or "runtimebroker" in low):
                    lvl = "MEDIUM" if ("denied" in low or "0x8007" in low) else "INFO"
                    emit("ETW", "Event", 0, line[:400], lvl)
    except Exception as e:
        emit("ETW", "Error", 0, "parse csv: " + str(e), "LOW")

def _try_logman(stop):
    tmpdir = tempfile.mkdtemp(prefix="fsniff_")
    etl = os.path.join(tmpdir, "trace.etl")
    csvp = os.path.join(tmpdir, "trace.csv")
    pf = os.path.join(tmpdir, "providers.txt")
    try:
        with open(pf, "w", encoding="utf-8") as f:
            for name, guid in ETW_PROVIDERS:
                f.write(guid + " 0xffffffffffffffff 5\n")
    except Exception as e:
        emit("ETW", "Error", 0, "provider file: " + str(e), "LOW")
        return False
    session = "Fsniff"
    _run(["logman", "stop", session, "-ets"], capture_output=True, timeout=20)
    r = _run(
        ["logman", "create", "trace", session, "-ow", "-o", etl,
         "-pf", pf, "-nb", "16", "16", "-bs", "1024", "-ets"],
        capture_output=True, timeout=30)
    if r.returncode != 0:
        emit("ETW", "Error", 0,
             "logman create: " + r.stderr.decode("utf-8", "replace")[:200],
             "LOW")
        return False
    STATUS.set("ETW", "green", "logman")
    STATUS.set("WPR", "gray", "not needed (logman)")
    while not stop.is_set():
        stop.wait(1.0)
    _run(["logman", "stop", session, "-ets"], capture_output=True, timeout=30)
    if os.path.isfile(etl):
        try:
            r = _run(["tracerpt", etl, "-of", "CSV", "-o", csvp, "-y"],
                     capture_output=True, timeout=90)
            if r.returncode == 0 and os.path.isfile(csvp):
                _parse_tracerpt_csv(csvp)
        except Exception as e:
            emit("ETW", "Error", 0, "tracerpt: " + str(e), "LOW")
    return True

def _try_wpr(stop):
    etl = os.path.join(tempfile.gettempdir(), "fsniff_wpr.etl")
    r = _run(
        ["wpr", "-start", "FileIO", "-start", "Registry", "-filemode"],
        capture_output=True, timeout=30)
    if r.returncode != 0:
        return False
    STATUS.set("ETW", "green", "WPR")
    STATUS.set("WPR", "green", "active")
    while not stop.is_set():
        stop.wait(1.0)
    _run(["wpr", "-stop", etl], capture_output=True, timeout=60)
    if os.path.isfile(etl):
        csvp = os.path.join(tempfile.gettempdir(), "fsniff_wpr.csv")
        try:
            _run(["tracerpt", etl, "-of", "CSV", "-o", csvp, "-y"],
                 capture_output=True, timeout=120)
            if os.path.isfile(csvp):
                _parse_tracerpt_csv(csvp)
        except Exception:
            pass
    return True

def collector_etw(stop):
    STATUS.set("ETW", "gray", "init")
    STATUS.set("WPR", "gray", "idle")
    if is_admin():
        if _try_pywintrace(stop):
            return
        if _try_logman(stop):
            return
        if _try_wpr(stop):
            return
        STATUS.set("ETW", "red", "tum yollar basarisiz")
        STATUS.set("WPR", "red", "not available")
    else:
        if _try_pywintrace(stop):
            return
        STATUS.set("ETW", "red", "admin yok")
        STATUS.set("WPR", "red", "admin yok")

# ---------------------------------------------------------------------------
# ProcMon
# ---------------------------------------------------------------------------
def find_procmon():
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.path.join(here, "Procmon64.exe"),
        os.path.join(here, "Procmon.exe"),
        r"C:\Tools\Procmon64.exe",
        r"C:\Sysinternals\Procmon64.exe",
        r"C:\SysinternalsSuite\Procmon64.exe",
    ]
    for c in cands:
        if os.path.isfile(c):
            return c
    for p in os.environ.get("PATH", "").split(os.pathsep):
        for nm in ("Procmon64.exe", "Procmon.exe"):
            c = os.path.join(p, nm)
            if os.path.isfile(c):
                return c
    return None

def _parse_procmon_csv(path):
    try:
        with open(path, "r", encoding="utf-16", errors="replace") as f:
            rd = csv.reader(f, delimiter="\t")
            first = True
            for row in rd:
                if first:
                    first = False
                    continue
                line = " | ".join(c for c in row if c)
                low = line.lower()
                if any(k in low for k in (
                        "denied", "0x80070005", "0x80070490", "0x80073d",
                        "access is denied", "wallpaper", "photos",
                        "runtimebroker", "transcoded", "personalization",
                        "shell", "theme")):
                    lvl = "MEDIUM" if ("denied" in low or "0x800" in low) else "INFO"
                    emit("ProcMon", "Event", 0, line[:400], lvl)
    except Exception as e:
        emit("ProcMon", "Error", 0, "parse csv: " + str(e), "LOW")

def _procmon_alive(name):
    try:
        r = _run(["tasklist", "/FI", "IMAGENAME eq " + name, "/NH"],
                 capture_output=True, timeout=10)
        out = r.stdout.decode("utf-8", "replace").lower()
        return name.lower() in out
    except Exception:
        return False

def _procmon_close_gracefully(name):
    try:
        _run(["taskkill", "/IM", name], capture_output=True, timeout=15)
    except Exception:
        pass
    for _ in range(40):
        time.sleep(0.5)
        if not _procmon_alive(name):
            return True
    try:
        _run(["taskkill", "/IM", name, "/F"], capture_output=True, timeout=15)
    except Exception:
        pass
    time.sleep(1.5)
    return False

def collector_procmon(stop, pml_holder):
    exe = find_procmon()
    if not exe:
        STATUS.set("ProcMon", "red", "Procmon64.exe yok")
        return
    exe_name = os.path.basename(exe)
    tmpdir = tempfile.mkdtemp(prefix="pml_")
    pml = os.path.join(tmpdir, "trace.pml")
    pml_holder["pml"] = pml
    try:
        subprocess.Popen(
            [exe, "/AcceptEula", "/Quiet", "/BackingFile", pml, "/Minimized"],
            creationflags=0x00000008)
    except Exception as e:
        STATUS.set("ProcMon", "red", "start: " + str(e))
        return
    t0 = time.time()
    while time.time() - t0 < 15 and not stop.is_set():
        if os.path.isfile(pml) and os.path.getsize(pml) > 0:
            break
        stop.wait(0.3)
    if not os.path.isfile(pml):
        STATUS.set("ProcMon", "red", "pml olusmadi")
        return
    STATUS.set("ProcMon", "green", "pml")
    while not stop.is_set():
        stop.wait(0.5)
    closed_ok = _procmon_close_gracefully(exe_name)
    if closed_ok:
        emit("ProcMon", "Event", 0, "ProcMon graceful close OK", "INFO")
    else:
        emit("ProcMon", "Error", 0,
             "ProcMon graceful close timed out, forced kill", "MEDIUM")
    try:
        sz = os.path.getsize(pml)
    except Exception:
        sz = 0
    if sz < 4096:
        STATUS.set("ProcMon", "red", "pml too small (%d B)" % sz)
        emit("ProcMon", "Error", 0,
             "PML bos veya cok kucuk (%d bytes), convert atlandi" % sz, "LOW")
        return
    csvp = os.path.join(tmpdir, "trace.csv")
    try:
        _run([exe, "/Quiet", "/OpenLog", pml, "/SaveAs", csvp],
             capture_output=True, timeout=180)
        if os.path.isfile(csvp) and os.path.getsize(csvp) > 0:
            _parse_procmon_csv(csvp)
            pml_holder["csv"] = csvp
        else:
            emit("ProcMon", "Error", 0,
                 "PML -> CSV cevrimi basarisiz (bos)", "LOW")
    except Exception as e:
        emit("ProcMon", "Error", 0, "convert: " + str(e), "LOW")

# ---------------------------------------------------------------------------
# Hook
# ---------------------------------------------------------------------------
class HookCollector(object):
    def __init__(self):
        self.hook = None
        self.proc = None
        self.win_hooks = []
        self.win_proc = None
        self.cwpret_ok = False
        self.winevent_ok = False

    def install(self):
        self._install_cwpret()
        self._install_winevent()
        if self.cwpret_ok and self.winevent_ok:
            STATUS.set("Hook", "green", "ok")
        elif self.winevent_ok:
            STATUS.set("Hook", "green", "winevent")
        elif self.cwpret_ok:
            STATUS.set("Hook", "green", "cwpret")
        else:
            STATUS.set("Hook", "red", "install failed")

    def _install_cwpret(self):
        try:
            LR = ctypes.c_ssize_t
            HOOKPROC = ctypes.WINFUNCTYPE(LR, ctypes.c_int, wt.WPARAM, wt.LPARAM)
            user32 = ctypes.windll.user32
            user32.SetWindowsHookExW.restype = ctypes.c_void_p
            user32.SetWindowsHookExW.argtypes = [
                ctypes.c_int, HOOKPROC, ctypes.c_void_p, wt.DWORD]
            user32.CallNextHookExW.restype = LR
            user32.CallNextHookExW.argtypes = [
                ctypes.c_void_p, ctypes.c_int, wt.WPARAM, wt.LPARAM]
            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentThreadId.restype = wt.DWORD

            class CWPRETSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("lResult", wt.LPARAM),
                    ("lParam", wt.LPARAM),
                    ("wParam", wt.WPARAM),
                    ("message", wt.UINT),
                    ("hwnd", wt.HWND),
                ]

            def proc(nCode, wParam, lParam):
                try:
                    if nCode >= 0:
                        cw = ctypes.cast(lParam, ctypes.POINTER(CWPRETSTRUCT)).contents
                        if cw.message in (0x0006, 0x001C):
                            cls = ctypes.create_unicode_buffer(256)
                            ttl = ctypes.create_unicode_buffer(512)
                            user32.GetClassNameW(cw.hwnd, cls, 256)
                            user32.GetWindowTextW(cw.hwnd, ttl, 512)
                            emit("Hook", "Window", 0,
                                 "msg=0x%04x class=%s title=%s" %
                                 (cw.message, cls.value, ttl.value), "INFO")
                except Exception:
                    pass
                try:
                    return user32.CallNextHookExW(None, nCode, wParam, lParam)
                except Exception:
                    return 0

            self.proc = HOOKPROC(proc)
            WH_CALLWNDPROCRET = 12
            tid = kernel32.GetCurrentThreadId()
            self.hook = user32.SetWindowsHookExW(WH_CALLWNDPROCRET, self.proc,
                                                  None, tid)
            if self.hook:
                self.cwpret_ok = True
                emit("Hook", "Window", 0,
                     "WH_CALLWNDPROCRET installed (tid=%d)" % tid, "INFO")
        except Exception as e:
            emit("Hook", "Error", 0, "cwpret: " + str(e), "LOW")

    def _install_winevent(self):
        try:
            user32 = ctypes.windll.user32
            WINEVENTPROC = ctypes.WINFUNCTYPE(
                None, ctypes.c_void_p, wt.DWORD, wt.HWND,
                ctypes.c_long, ctypes.c_long, wt.DWORD, wt.DWORD)
            user32.SetWinEventHook.restype = ctypes.c_void_p
            user32.SetWinEventHook.argtypes = [
                wt.DWORD, wt.DWORD, ctypes.c_void_p, WINEVENTPROC,
                wt.DWORD, wt.DWORD, wt.DWORD]
            user32.UnhookWinEvent.argtypes = [ctypes.c_void_p]

            names = {0x0003: "FOREGROUND", 0x8000: "CREATE", 0x8002: "SHOW"}

            def cb(hHook, event, hwnd, idObject, idChild, tid, evtTime):
                try:
                    cls = ctypes.create_unicode_buffer(256)
                    ttl = ctypes.create_unicode_buffer(512)
                    user32.GetClassNameW(hwnd, cls, 256)
                    user32.GetWindowTextW(hwnd, ttl, 512)
                    pid = wt.DWORD()
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    nm = names.get(event, hex(event))
                    emit("Hook", "Window", pid.value,
                         "WinEvent %s class=%s title=%s" %
                         (nm, cls.value, ttl.value), "INFO")
                except Exception:
                    pass

            self.win_proc = WINEVENTPROC(cb)
            flags = 0x0000 | 0x0002
            for ev in (0x0003, 0x8000, 0x8002):
                h = user32.SetWinEventHook(ev, ev, None, self.win_proc,
                                           0, 0, flags)
                if h:
                    self.win_hooks.append(h)
            if self.win_hooks:
                self.winevent_ok = True
                emit("Hook", "Window", 0,
                     "WinEventHook installed (%d)" % len(self.win_hooks), "INFO")
        except Exception as e:
            emit("Hook", "Error", 0, "winevent: " + str(e), "LOW")

    def uninstall(self):
        try:
            if self.hook:
                ctypes.windll.user32.UnhookWindowsHookEx(ctypes.c_void_p(self.hook))
        except Exception:
            pass
        try:
            for h in self.win_hooks:
                ctypes.windll.user32.UnhookWinEvent(ctypes.c_void_p(h))
        except Exception:
            pass
        self.win_hooks = []

# ---------------------------------------------------------------------------
# WinRT
# ---------------------------------------------------------------------------
def collector_winrt(stop):
    STATUS.set("WinRT", "gray", "probe")
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "try {"
        "  [void][Windows.System.UserProfile.UserProfilePersonalizationSettings,"
        "Windows.System.UserProfile, ContentType=WindowsRuntime];"
        "  $s=[Windows.System.UserProfile.UserProfilePersonalizationSettings]"
        "::IsSupported();"
        "  Write-Output ('IsSupported=' + $s);"
        "} catch { Write-Output ('ERR:' + $_.Exception.Message) }"
        "try {"
        "  $img=[Windows.System.UserProfile.LockScreen,"
        "Windows.System.UserProfile, ContentType=WindowsRuntime]"
        "::OriginalImageFile;"
        "  Write-Output ('LockScreenOriginalImageFile=' + $img);"
        "} catch { Write-Output ('ERR2:' + $_.Exception.Message) }"
        "try {"
        "  $pkg=Get-AppxPackage Microsoft.Windows.Photos | "
        "Select-Object Name,Status,Version,PackageFullName | "
        "ConvertTo-Json -Compress;"
        "  Write-Output ('PHOTOS=' + $pkg);"
        "} catch { Write-Output ('ERR3:' + $_.Exception.Message) }"
    )
    try:
        r = _run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
             "-Command", ps],
            capture_output=True, timeout=30)
        out = r.stdout.decode("utf-8", "replace") + \
              r.stderr.decode("utf-8", "replace")
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            lvl = "INFO"
            if "IsSupported=False" in line:
                lvl = "HIGH"
            elif "ERR" in line:
                lvl = "LOW"
            emit("WinRT", "Event", 0, line[:400], lvl)
        if "IsSupported=False" in out:
            emit("WinRT", "Error", 0,
                 "WinRT wallpaper API seviyesinde kisilestirme "
                 "desteklenmiyor diyor. Policy/ACL/capability katmaninda "
                 "engel var.", "HIGH")
        STATUS.set("WinRT", "green", "ok")
    except Exception as e:
        STATUS.set("WinRT", "red", "powershell: " + str(e))
    while not stop.is_set():
        stop.wait(5.0)

# ---------------------------------------------------------------------------
# Probes A-K
# ---------------------------------------------------------------------------
def probe_policy():
    emit("Diag", "Diag", 0, "== A: personalization policy ==", "INFO")
    keys = [
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
         "NoChangingWallpaper"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
         "NoDispBackgroundPage"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
         "DisableLogonBackgroundImage"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
         "NoLockScreen"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
         "NoChangingLockScreen"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
         "NoChangingWallpaper"),
        (winreg.HKEY_CURRENT_USER if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
         "NoChangingWallpaper"),
        (winreg.HKEY_CURRENT_USER if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
         "NoDispBackgroundPage"),
        (winreg.HKEY_CURRENT_USER if winreg else None,
         r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
         "NoChangingWallpaper"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP",
         "LockScreenImagePath"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP",
         "LockScreenImageUrl"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP",
         "DesktopImagePath"),
        (winreg.HKEY_LOCAL_MACHINE if winreg else None,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP",
         "DesktopImageUrl"),
    ]
    for root, path, name in keys:
        v = reg_get(root, path, name) if root else None
        if v is None:
            emit("Diag", "Diag", 0, "[OK] %s\\%s = (unset)" % (path, name), "OK")
        else:
            try:
                is_zero = (int(v) == 0) if str(v).isdigit() else False
            except Exception:
                is_zero = False
            if is_zero:
                emit("Diag", "Diag", 0, "[OK] %s\\%s = 0" % (path, name), "OK")
            else:
                emit("Diag", "Diag", 0,
                     "[FAIL] %s\\%s = %s (policy aktif)" % (path, name, v),
                     "HIGH")

def probe_appprivacy():
    emit("Diag", "Diag", 0, "== B: AppPrivacy force-deny ==", "INFO")
    path = r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    low = {"LetAppsAccessCamera", "LetAppsAccessLocation"}
    names = ["LetAppsAccessAccountInfo", "LetAppsAccessUserData",
             "LetAppsAccessPicturesLibrary", "LetAppsAccessDocumentsLibrary",
             "LetAppsRunInBackground", "LetAppsAccessCamera",
             "LetAppsAccessLocation"]
    if not reg_key_exists(winreg.HKEY_LOCAL_MACHINE, path):
        emit("Diag", "Diag", 0, "[OK] AppPrivacy key yok", "OK")
        return
    for nm in names:
        v = reg_get(winreg.HKEY_LOCAL_MACHINE, path, nm)
        if v is None:
            continue
        try:
            iv = int(v)
        except Exception:
            continue
        if iv == 0:
            sev = "LOW" if nm in low else "HIGH"
            emit("Diag", "Diag", 0, "[FAIL] %s = 0 (Force Deny)" % nm, sev)

def probe_consentstore():
    emit("Diag", "Diag", 0, "== C: ConsentStore ==", "INFO")
    caps = ["userAccountInformation", "picturesLibrary", "documentsLibrary",
            "broadFileSystemAccess", "graphicsCaptureProgrammatic"]
    for root, tag in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"),
                      (winreg.HKEY_CURRENT_USER, "HKCU")]:
        base = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
                r"\ConsentStore")
        for cap in caps:
            v = reg_get(root, base + "\\" + cap, "Value")
            if v is None:
                emit("Diag", "Diag", 0, "[OK] %s %s = unset" % (tag, cap), "OK")
            elif str(v) == "Deny":
                emit("Diag", "Diag", 0, "[FAIL] %s %s = Deny" % (tag, cap), "HIGH")
            else:
                emit("Diag", "Diag", 0, "[OK] %s %s = %s" % (tag, cap, v), "OK")

def probe_disallowrun():
    emit("Diag", "Diag", 0, "== D: DisallowRun ==", "INFO")
    p = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    dr = reg_get(winreg.HKEY_CURRENT_USER, p, "DisallowRun")
    if dr != 1:
        emit("Diag", "Diag", 0, "[OK] DisallowRun != 1", "OK")
        return
    sub = p + r"\DisallowRun"
    if not reg_key_exists(winreg.HKEY_CURRENT_USER, sub):
        emit("Diag", "Diag", 0, "[OK] alt anahtar yok", "OK")
        return
    targets = {"photos.exe", "runtimebroker.exe", "systemsettings.exe",
               "backgroundtaskhost.exe", "applicationframehost.exe",
               "winrt.runtime.dll"}
    try:
        h = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ)
        try:
            i = 0
            while True:
                try:
                    nm, val, _ = winreg.EnumValue(h, i)
                    i += 1
                except OSError:
                    break
                if str(val).lower() in targets:
                    emit("Diag", "Diag", 0,
                         "[FAIL] DisallowRun %s = %s" % (nm, val), "HIGH")
        finally:
            winreg.CloseKey(h)
    except Exception:
        pass

def probe_ifeo():
    emit("Diag", "Diag", 0, "== E: IFEO ==", "INFO")
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for exe in ["RuntimeBroker.exe", "SystemSettings.exe", "Photos.exe",
                "ApplicationFrameHost.exe"]:
        p = base + "\\" + exe
        if not reg_key_exists(winreg.HKEY_LOCAL_MACHINE, p):
            continue
        dbg = reg_get(winreg.HKEY_LOCAL_MACHINE, p, "Debugger")
        if dbg:
            emit("Diag", "Diag", 0, "[FAIL] IFEO %s Debugger = %s" % (exe, dbg),
                 "HIGH")
        mo = reg_get(winreg.HKEY_LOCAL_MACHINE, p, "MitigationOptions")
        if mo:
            try:
                iv = int(mo) if not isinstance(mo, bytes) else int.from_bytes(mo, "little")
                if iv & (1 << 32):
                    emit("Diag", "Diag", 0,
                         "[WARN] IFEO %s MitigationOptions=0x%x" % (exe, iv),
                         "MEDIUM")
            except Exception:
                pass

def probe_shell_verb():
    emit("Diag", "Diag", 0, "== F: shell verb ==", "INFO")
    try:
        import winreg as wr
    except Exception:
        return
    bases = [
        r"SystemFileAssociations\.jpg\shell\setaswallpaper",
        r"SystemFileAssociations\.png\shell\setaswallpaper",
        r"SystemFileAssociations\image\shell\setaswallpaper",
    ]
    any_found = False
    for b in bases:
        try:
            h = wr.OpenKey(wr.HKEY_CLASSES_ROOT, b, 0, wr.KEY_READ)
            wr.CloseKey(h)
            any_found = True
            cmd = reg_get(wr.HKEY_CLASSES_ROOT, b + r"\command", "")
            emit("Diag", "Diag", 0, "[OK] %s cmd=%s" % (b, cmd), "OK")
        except Exception:
            pass
    if not any_found:
        emit("Diag", "Diag", 0,
             "[FAIL] setaswallpaper verb yok. Explorer'da sag tik > "
             "Set as desktop background kaybolmus.", "HIGH")

def probe_transcode_write():
    emit("Diag", "Diag", 0, "== H: TranscodedWallpaper write ==", "INFO")
    p = os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Themes\TranscodedWallpaper")
    if not os.path.isfile(p):
        emit("Diag", "Diag", 0, "[WARN] %s yok" % p, "MEDIUM")
        return
    try:
        with open(p, "ab") as f:
            f.write(b"")
        emit("Diag", "Diag", 0, "[OK] yazma izni var", "OK")
    except PermissionError as e:
        emit("Diag", "Diag", 0, "[FAIL] PermissionError: " + str(e), "HIGH")
    except Exception as e:
        emit("Diag", "Diag", 0, "[WARN] " + str(e), "MEDIUM")

def probe_acl():
    emit("Diag", "Diag", 0, "== I: ACL dump ==", "INFO")
    try:
        r = _run(["icacls", r"HKCU\Control Panel\Desktop"],
                 capture_output=True, timeout=20)
        out = r.stdout.decode("utf-8", "replace") + \
              r.stderr.decode("utf-8", "replace")
        for line in out.splitlines():
            if not line.strip():
                continue
            if "DENY" in line.upper():
                emit("Diag", "Diag", 0, "[FAIL] icacls DENY: " + line, "HIGH")
            else:
                emit("Diag", "Diag", 0, "icacls " + line, "INFO")
    except Exception as e:
        emit("Diag", "Diag", 0, "[WARN] icacls: " + str(e), "LOW")

def probe_services():
    emit("Diag", "Diag", 0, "== J: services ==", "INFO")
    for svc in ["Themes", "AppXSvc", "ClipSVC", "StateRepository",
                "TokenBroker", "Dwm", "ShellHWDetection",
                "ShellExperienceHost"]:
        try:
            r = _run(["sc", "query", svc], capture_output=True, timeout=10)
            out = (r.stdout + r.stderr).decode("utf-8", "replace")
            state = "?"
            for line in out.splitlines():
                if "STATE" in line:
                    state = line.strip()
                    break
            if "RUNNING" in state:
                emit("Diag", "Diag", 0, "[OK] %s %s" % (svc, state), "OK")
            elif "STOPPED" in state:
                emit("Diag", "Diag", 0, "[FAIL] %s %s" % (svc, state), "HIGH")
            else:
                emit("Diag", "Diag", 0, "[WARN] %s %s" % (svc, state), "LOW")
        except Exception as e:
            emit("Diag", "Diag", 0, "[WARN] sc %s: %s" % (svc, e), "LOW")

def probe_explorer_hints():
    emit("Diag", "Diag", 0, "== K: explorer policy ==", "INFO")
    p = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    v = reg_get(winreg.HKEY_CURRENT_USER, p, "ForceClassicControlPanel")
    if v == 1:
        emit("Diag", "Diag", 0, "[INFO] ForceClassicControlPanel=1", "LOW")
    v = reg_get(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoActiveDesktop")
    if v == 1:
        emit("Diag", "Diag", 0, "[INFO] NoActiveDesktop=1 (legacy)", "INFO")

def run_all_probes():
    for fn in [probe_policy, probe_appprivacy, probe_consentstore,
               probe_disallowrun, probe_ifeo, probe_shell_verb,
               probe_transcode_write, probe_acl, probe_services,
               probe_explorer_hints]:
        try:
            fn()
        except Exception as e:
            emit("Diag", "Error", 0, "probe %s: %s" % (fn.__name__, e), "LOW")

# ---------------------------------------------------------------------------
# Marker
# ---------------------------------------------------------------------------
def is_relevant(ev):
    if ev.source in ("RegPoll", "FileWatch"):
        return True
    d = (ev.detail or "").lower()
    for kw in ("wallpaper", "photos", "runtimebroker", "personaliz",
               "lockscreen", "lock screen", "transcoded", "userprofile",
               "setaswallpaper", "set as"):
        if kw in d:
            return True
    return False

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
class T:
    BG       = "#181825"
    PANEL    = "#1e1e2e"
    PANEL2   = "#252535"
    PANEL3   = "#2a2a3c"
    BORDER   = "#313244"
    FG       = "#cdd6f4"
    FG_DIM   = "#7f849c"
    FG_MUTE  = "#585b70"
    ACCENT   = "#89b4fa"
    ACCENT2  = "#74a0e8"
    GREEN    = "#a6e3a1"
    YELLOW   = "#f9e2af"
    ORANGE   = "#fab387"
    RED      = "#f38ba8"
    PURPLE   = "#cba6f7"
    SELECT   = "#45475a"
    SCROLL   = "#585b70"   # visible thumb
    SCROLL_H = "#7f849c"   # hover thumb

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont

class Led(tk.Canvas):
    def __init__(self, parent, size=10, bg=T.PANEL):
        super().__init__(parent, width=size, height=size, bg=bg,
                         highlightthickness=0, bd=0)
        self.size = size
        self.dot = self.create_oval(1, 1, size - 1, size - 1,
                                     fill=T.FG_MUTE, outline="")
    def set_color(self, color):
        try:
            self.itemconfig(self.dot, fill=color)
        except Exception:
            pass

class SourceRow(tk.Frame):
    def __init__(self, parent, name):
        super().__init__(parent, bg=T.PANEL, height=26)
        self.pack_propagate(False)
        self.led = Led(self, size=10, bg=T.PANEL)
        self.led.pack(side=tk.LEFT, padx=(10, 8))
        self.name = tk.Label(self, text=name, bg=T.PANEL, fg=T.FG,
                             anchor="w", font=("Segoe UI", 9))
        self.name.pack(side=tk.LEFT)
        self.note = tk.Label(self, text="", bg=T.PANEL, fg=T.FG_DIM,
                             anchor="e", font=("Segoe UI", 8))
        self.note.pack(side=tk.RIGHT, padx=(4, 10))
    def set_state(self, state, note=""):
        color = {"green": T.GREEN, "gray": T.FG_MUTE,
                 "red": T.RED, "yellow": T.YELLOW}.get(state, T.FG_MUTE)
        self.led.set_color(color)
        self.note.configure(text=(note or "")[:22])

class Chip(tk.Label):
    def __init__(self, parent, text, var, command=None, bg=T.PANEL):
        super().__init__(parent, text=text, padx=8, pady=2,
                         font=("Segoe UI", 8), cursor="hand2",
                         bg=T.PANEL2, fg=T.FG_DIM, bd=0)
        self.var = var
        self.command = command
        self.bind("<Button-1>", self._toggle)
        self._refresh()
    def _toggle(self, _e=None):
        self.var.set(not self.var.get())
        self._refresh()
        if self.command:
            try: self.command()
            except Exception: pass
    def _refresh(self):
        if self.var.get():
            self.configure(bg=T.ACCENT, fg=T.PANEL)
        else:
            self.configure(bg=T.PANEL2, fg=T.FG_DIM)

class App(object):
    def __init__(self, root, admin_mode):
        self.root = root
        self.admin_mode = admin_mode
        self.stop = StopFlag()
        self.collectors = []
        self.hook_collector = None
        self.pml_holder = {}
        self.events = []
        self.marker_time = None
        self.marker_job = None
        self.src_filter = {s: tk.BooleanVar(value=True) for s in ALL_SOURCES}
        self.type_filter = {t: tk.BooleanVar(value=True) for t in ALL_TYPES}
        self.error_only = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar(value="")
        self.events_count = 0
        self.src_rows = {}
        self._setup_theme()
        self._init_status()
        self._build_ui()
        self._pump()
        self._status_pump()

    def _setup_theme(self):
        try:
            f = tkfont.nametofont("TkDefaultFont")
            f.configure(family="Segoe UI", size=9)
        except Exception:
            pass
        try:
            f = tkfont.nametofont("TkTextFont")
            f.configure(family="Segoe UI", size=9)
        except Exception:
            pass
        try:
            f = tkfont.nametofont("TkFixedFont")
            f.configure(family="Consolas", size=9)
        except Exception:
            pass
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".", background=T.BG, foreground=T.FG,
                    fieldbackground=T.PANEL, bordercolor=T.BORDER,
                    lightcolor=T.BORDER, darkcolor=T.BORDER,
                    troughcolor=T.PANEL2, focuscolor=T.ACCENT)
        s.configure("TFrame", background=T.BG)
        s.configure("Panel.TFrame", background=T.PANEL)
        s.configure("Toolbar.TFrame", background=T.PANEL)
        s.configure("TLabel", background=T.BG, foreground=T.FG)
        s.configure("Panel.TLabel", background=T.PANEL, foreground=T.FG)
        s.configure("Muted.TLabel", background=T.BG, foreground=T.FG_DIM)
        s.configure("TButton", background=T.PANEL2, foreground=T.FG,
                    borderwidth=0, focuscolor=T.PANEL2, padding=(10, 6),
                    font=("Segoe UI", 9))
        s.map("TButton",
              background=[("active", T.SELECT), ("pressed", T.SELECT),
                          ("disabled", T.PANEL2)],
              foreground=[("disabled", T.FG_MUTE)])
        s.configure("Accent.TButton", background=T.ACCENT, foreground=T.PANEL,
                    borderwidth=0, focuscolor=T.ACCENT, padding=(14, 6),
                    font=("Segoe UI Semibold", 9))
        s.map("Accent.TButton",
              background=[("active", T.ACCENT2), ("pressed", T.ACCENT2),
                          ("disabled", T.PANEL3)],
              foreground=[("disabled", T.FG_MUTE)])
        s.configure("Danger.TButton", background=T.RED, foreground=T.PANEL,
                    borderwidth=0, focuscolor=T.RED, padding=(14, 6),
                    font=("Segoe UI Semibold", 9))
        s.map("Danger.TButton",
              background=[("active", "#e07a90"), ("pressed", "#e07a90"),
                          ("disabled", T.PANEL3)],
              foreground=[("disabled", T.FG_MUTE)])
        s.configure("Warn.TButton", background=T.YELLOW, foreground=T.PANEL,
                    borderwidth=0, focuscolor=T.YELLOW, padding=(14, 6),
                    font=("Segoe UI Semibold", 9))
        s.map("Warn.TButton",
              background=[("active", "#d8bf8a"), ("pressed", "#d8bf8a"),
                          ("disabled", T.PANEL3)],
              foreground=[("disabled", T.FG_MUTE)])
        s.configure("Treeview",
                    background=T.PANEL, foreground=T.FG,
                    fieldbackground=T.PANEL, rowheight=22,
                    borderwidth=0, font=("Consolas", 9))
        s.map("Treeview",
              background=[("selected", T.SELECT)],
              foreground=[("selected", T.FG)])
        s.configure("Treeview.Heading",
                    background=T.PANEL2, foreground=T.FG_DIM,
                    borderwidth=0, relief="flat", padding=(6, 6),
                    font=("Segoe UI Semibold", 8))
        s.map("Treeview.Heading",
              background=[("active", T.PANEL3)],
              foreground=[("active", T.FG)])
        # Highly visible scrollbars
        for style_name in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            s.configure(style_name,
                        background=T.SCROLL,
                        troughcolor=T.PANEL2,
                        bordercolor=T.PANEL,
                        arrowcolor=T.FG,
                        gripcount=0,
                        relief="flat",
                        borderwidth=0,
                        width=14)
            s.map(style_name,
                  background=[("active", T.SCROLL_H),
                              ("pressed", T.SCROLL_H),
                              ("!active", T.SCROLL)])
        s.configure("TEntry", fieldbackground=T.PANEL2, foreground=T.FG,
                    bordercolor=T.BORDER, insertcolor=T.FG,
                    lightcolor=T.BORDER, darkcolor=T.BORDER, padding=4)
        s.configure("TSeparator", background=T.BORDER)

    def _init_status(self):
        STATUS.set("System", "green", "internal")
        STATUS.set("Diag", "green", "probes ready")
        for s in ALL_SOURCES:
            if s in ("System", "Diag"):
                continue
            STATUS.set(s, "gray", "idle")

    def _build_ui(self):
        r = self.root
        r.title("Fsniff " + TAG + " - Windows forensic diagnostic")
        r.geometry("1320x820")
        r.configure(bg=T.BG)
        r.minsize(1000, 600)

        tb = ttk.Frame(r, style="Toolbar.TFrame", padding=(10, 8))
        tb.pack(side=tk.TOP, fill=tk.X)
        tk.Label(tb, text="FSNIFF " + TAG, bg=T.PANEL, fg=T.ACCENT,
                 font=("Segoe UI Semibold", 11)).pack(side=tk.LEFT, padx=(0, 16))
        self.btn_start = ttk.Button(tb, text="START", style="Accent.TButton",
                                    command=self.on_start)
        self.btn_start.pack(side=tk.LEFT, padx=2)
        self.btn_stop = ttk.Button(tb, text="STOP", style="Danger.TButton",
                                   command=self.on_stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=2)
        self.btn_marker = ttk.Button(tb, text="MARKER", style="Warn.TButton",
                                     command=self.on_marker, state=tk.DISABLED)
        self.btn_marker.pack(side=tk.LEFT, padx=(10, 2))
        tk.Frame(tb, width=1, bg=T.BORDER).pack(side=tk.LEFT, fill=tk.Y, padx=12)
        for label, cmd in (
            ("SPI Test", self.on_spi_test),
            ("Photos ReReg", self.on_photos_rereg),
            ("Shell Restore", self.on_shell_restore),
            ("Open PML", self.on_open_pml),
            ("CSV", self.on_export_csv),
            ("JSON", self.on_export_json),
        ):
            b = ttk.Button(tb, text=label, command=cmd)
            b.pack(side=tk.RIGHT, padx=2)
            if label == "Open PML":
                self.btn_pml = b
                b.configure(state=tk.DISABLED)

        body = ttk.Frame(r, style="TFrame", padding=0)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=T.PANEL, width=260)
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)
        tk.Label(left, text="SOURCES", bg=T.PANEL, fg=T.FG_DIM,
                 font=("Segoe UI Semibold", 8), anchor="w"
                 ).pack(side=tk.TOP, fill=tk.X, padx=12, pady=(12, 6))
        for s in ALL_SOURCES:
            row = SourceRow(left, s)
            row.pack(side=tk.TOP, fill=tk.X)
            self.src_rows[s] = row
        tk.Frame(left, bg=T.PANEL).pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        leg = tk.Frame(left, bg=T.PANEL)
        leg.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=10)
        for color, text in ((T.GREEN, "active"), (T.YELLOW, "warning"),
                             (T.RED, "failed"), (T.FG_MUTE, "idle")):
            fr = tk.Frame(leg, bg=T.PANEL)
            fr.pack(side=tk.TOP, anchor="w", pady=1)
            led = Led(fr, size=8, bg=T.PANEL)
            led.pack(side=tk.LEFT)
            led.set_color(color)
            tk.Label(fr, text="  " + text, bg=T.PANEL, fg=T.FG_DIM,
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

        right = ttk.Frame(body, style="TFrame")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        fb = tk.Frame(right, bg=T.BG, padx=10, pady=8)
        fb.pack(side=tk.TOP, fill=tk.X)
        tk.Label(fb, text="SOURCE", bg=T.BG, fg=T.FG_DIM,
                 font=("Segoe UI Semibold", 7)).grid(row=0, column=0,
                                                     sticky="w", padx=(0, 6))
        sf = tk.Frame(fb, bg=T.BG)
        sf.grid(row=0, column=1, sticky="w")
        for s in ALL_SOURCES:
            Chip(sf, s, self.src_filter[s], command=self.refresh_view,
                 bg=T.BG).pack(side=tk.LEFT, padx=1)
        tk.Label(fb, text="TYPE", bg=T.BG, fg=T.FG_DIM,
                 font=("Segoe UI Semibold", 7)).grid(row=1, column=0,
                                                     sticky="w",
                                                     padx=(0, 6), pady=(6, 0))
        tf = tk.Frame(fb, bg=T.BG)
        tf.grid(row=1, column=1, sticky="w", pady=(6, 0))
        for t in ALL_TYPES:
            Chip(tf, t, self.type_filter[t], command=self.refresh_view,
                 bg=T.BG).pack(side=tk.LEFT, padx=1)
        sf2 = tk.Frame(fb, bg=T.BG)
        sf2.grid(row=0, column=2, rowspan=2, sticky="e", padx=(12, 0))
        self.err_cb = tk.Checkbutton(
            sf2, text="Only errors", variable=self.error_only,
            command=self.refresh_view, bg=T.BG, fg=T.FG,
            selectcolor=T.PANEL2, activebackground=T.BG,
            activeforeground=T.FG, bd=0, highlightthickness=0,
            font=("Segoe UI", 9))
        self.err_cb.pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(sf2, text="Search:", bg=T.BG, fg=T.FG_DIM,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        ent = tk.Entry(sf2, textvariable=self.search_var, width=28,
                       bg=T.PANEL2, fg=T.FG, insertbackground=T.FG,
                       bd=0, highlightthickness=1,
                       highlightbackground=T.BORDER,
                       highlightcolor=T.ACCENT, font=("Segoe UI", 9))
        ent.pack(side=tk.LEFT, ipady=3)
        ent.bind("<KeyRelease>", lambda _e: self.refresh_view())
        fb.columnconfigure(1, weight=1)

        # events grid: tree + v scroll + h scroll
        ew = tk.Frame(right, bg=T.BG)
        ew.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=0)

        cols = ("time", "source", "type", "pid", "level", "detail")
        self.tree = ttk.Treeview(ew, columns=cols, show="headings",
                                 selectmode="browse")
        for c, w, a, st in (
                ("time", 110, "w", False),
                ("source", 90, "w", False),
                ("type", 90, "w", False),
                ("pid", 60, "e", False),
                ("level", 70, "w", False),
                ("detail", 1400, "w", True)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, minwidth=40, anchor=a, stretch=st)

        ysb = ttk.Scrollbar(ew, orient="vertical",
                            style="Vertical.TScrollbar",
                            command=self.tree.yview)
        xsb = ttk.Scrollbar(ew, orient="horizontal",
                            style="Horizontal.TScrollbar",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        ew.rowconfigure(0, weight=1)
        ew.columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

        self.tree.tag_configure("HIGH",   foreground=T.RED)
        self.tree.tag_configure("MEDIUM", foreground=T.ORANGE)
        self.tree.tag_configure("LOW",    foreground=T.YELLOW)
        self.tree.tag_configure("OK",     foreground=T.GREEN)
        self.tree.tag_configure("INFO",   foreground=T.FG)

        sb = tk.Frame(r, bg=T.PANEL, height=26)
        sb.pack(side=tk.BOTTOM, fill=tk.X)
        sb.pack_propagate(False)
        self.status_lbl = tk.Label(sb, text="ready", bg=T.PANEL, fg=T.FG_DIM,
                                   anchor="w", font=("Segoe UI", 8))
        self.status_lbl.pack(side=tk.LEFT, padx=12)
        self.log_lbl = tk.Label(sb, text=("log: " + LIVE_LOG_PATH),
                                bg=T.PANEL, fg=T.FG_MUTE, anchor="e",
                                font=("Segoe UI", 8))
        self.log_lbl.pack(side=tk.RIGHT, padx=12)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _status_pump(self):
        try:
            allst = STATUS.all()
            for name, (state, note) in allst.items():
                row = self.src_rows.get(name)
                if row:
                    row.set_state(state, note)
            ready = sum(1 for s in ALL_SOURCES
                        if allst.get(s, ("gray", ""))[0] == "green")
            total = len(ALL_SOURCES)
            dropped = BUS.dropped
            self.status_lbl.configure(
                text="events=%d  dropped=%d  sources=%d/%d" %
                     (self.events_count, dropped, ready, total))
        except Exception:
            pass
        self.root.after(500, self._status_pump)

    def _pump(self):
        try:
            evs = BUS.drain(500)
            for e in evs:
                self.events.append(e)
            self.events_count = len(self.events)
            if evs:
                self._insert_batch(evs)
        except Exception:
            pass
        self.root.after(150, self._pump)

    def _passes_filter(self, ev):
        try:
            if not self.src_filter.get(ev.source, tk.BooleanVar()).get():
                return False
        except Exception:
            pass
        try:
            if not self.type_filter.get(ev.type, tk.BooleanVar()).get():
                return False
        except Exception:
            pass
        if self.error_only.get() and ev.level not in ("HIGH", "MEDIUM"):
            return False
        s = self.search_var.get().strip().lower()
        if s and s not in (ev.detail or "").lower():
            return False
        return True

    def _row_tag(self, ev):
        return ev.level if ev.level in ("HIGH", "MEDIUM", "LOW", "OK") else "INFO"

    def _insert_batch(self, evs):
        for e in evs:
            if not self._passes_filter(e):
                continue
            self.tree.insert("", "end", values=(
                e.fmt_time(), e.source, e.type, e.pid, e.level,
                (e.detail or "")[:500]), tags=(self._row_tag(e),))
        n = len(self.tree.get_children())
        if n > 5000:
            for iid in self.tree.get_children()[:n - 4000]:
                self.tree.delete(iid)
        try:
            self.tree.see(self.tree.get_children()[-1])
        except Exception:
            pass

    def refresh_view(self):
        try:
            for iid in self.tree.get_children():
                self.tree.delete(iid)
            for e in self.events[-5000:]:
                if not self._passes_filter(e):
                    continue
                self.tree.insert("", "end", values=(
                    e.fmt_time(), e.source, e.type, e.pid, e.level,
                    (e.detail or "")[:500]), tags=(self._row_tag(e),))
        except Exception:
            pass

    def on_start(self):
        emit("System", "System", 0,
             "trace starting (admin=%s)" % self.admin_mode, "INFO")
        def spawn(fn, *a, name=None):
            def runner():
                try:
                    fn(*a)
                except Exception as e:
                    startup_log("collector %s crashed: %s" % (fn.__name__, e))
                    live_log("[FATAL] collector " + fn.__name__ + ": " + str(e))
            t = threading.Thread(target=runner,
                                 name=(name or fn.__name__), daemon=True)
            t.start()
            return t
        self.collectors = [
            spawn(collector_regpoll, self.stop),
            spawn(collector_filewatch, self.stop),
            spawn(collector_win32, self.stop),
            spawn(collector_proc, self.stop),
            spawn(collector_evtlog, self.stop),
            spawn(collector_wmi, self.stop),
            spawn(collector_etw, self.stop),
            spawn(collector_procmon, self.stop, self.pml_holder),
            spawn(collector_winrt, self.stop),
        ]
        try:
            self.hook_collector = HookCollector()
            self.hook_collector.install()
        except Exception as e:
            STATUS.set("Hook", "red", str(e)[:30])
        threading.Thread(target=run_all_probes, name="probes",
                         daemon=True).start()
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_marker.configure(state=tk.NORMAL)
        emit("System", "System", 0, "trace started", "INFO")

    def on_stop(self):
        emit("System", "System", 0, "trace stopping", "INFO")
        self.stop.set()
        if self.hook_collector:
            try: self.hook_collector.uninstall()
            except Exception: pass
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)
        self.btn_marker.configure(state=tk.DISABLED)
        if self.pml_holder.get("pml") and os.path.isfile(self.pml_holder["pml"]):
            self.btn_pml.configure(state=tk.NORMAL)
        for t in self.collectors:
            try: t.join(timeout=30)
            except Exception: pass
        summary = ("=== SUMMARY: events=%d dropped=%d log=%s ===" %
                   (self.events_count, BUS.dropped, LIVE_LOG_PATH))
        emit("System", "System", 0, summary, "INFO")

    def on_marker(self):
        self.marker_time = time.time()
        emit("Diag", "Marker", 0, "MARKER pressed", "INFO")
        if self.marker_job:
            try: self.root.after_cancel(self.marker_job)
            except Exception: pass
        self.marker_job = self.root.after(6000, self._marker_check)

    def _marker_check(self):
        if not self.marker_time:
            return
        t0 = self.marker_time
        rel = [e for e in BUS.history if e.ts > t0 and is_relevant(e)]
        if not rel:
            msg = ("Hedef uygulama (Photos.exe) Set As tiklandiginda "
                   "hicbir registry / dosya / API cagrisi yapmamis. "
                   "Sorun Windows katmaninda degil, uygulamanin kendisinde.")
            emit("Diag", "Error", 0, msg, "HIGH")
            try:
                messagebox.showwarning("Marker watchdog", msg)
            except Exception:
                pass
        else:
            emit("Diag", "Diag", 0,
                 "Marker sonrasi %d ilgili event yakalandi." % len(rel), "INFO")

    def on_export_json(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump([{
                    "ts": e.ts, "source": e.source, "type": e.type,
                    "pid": e.pid, "level": e.level, "detail": e.detail,
                } for e in self.events], f, ensure_ascii=False, indent=2)
            emit("System", "System", 0, "exported JSON -> " + p, "OK")
        except Exception as e:
            messagebox.showerror("Export JSON", str(e))

    def on_export_csv(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["ts", "time", "source", "type", "pid",
                            "level", "detail"])
                for e in self.events:
                    w.writerow([e.ts, e.fmt_time(), e.source, e.type,
                                e.pid, e.level, e.detail])
            emit("System", "System", 0, "exported CSV -> " + p, "OK")
        except Exception as e:
            messagebox.showerror("Export CSV", str(e))

    def on_open_pml(self):
        pml = self.pml_holder.get("pml")
        if not pml or not os.path.isfile(pml):
            return
        exe = find_procmon()
        if not exe:
            messagebox.showerror("ProcMon", "Procmon64.exe bulunamadi.")
            return
        try:
            subprocess.Popen([exe, "/OpenLog", pml])
        except Exception as e:
            messagebox.showerror("ProcMon", str(e))

    def on_shell_restore(self):
        try:
            if winreg is None:
                return
            base = r"SystemFileAssociations\.jpg\shell\setaswallpaper"
            cmd = r'rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0'
            k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0,
                                   winreg.KEY_WRITE)
            winreg.SetValueEx(k, "MUIVerb", 0, winreg.REG_SZ, "@shell32.dll,-51390")
            winreg.CloseKey(k)
            ck = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                                    base + r"\command", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(ck, "", 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(ck)
            emit("Diag", "Diag", 0, "[OK] setaswallpaper verb yazildi.", "OK")
        except Exception as e:
            emit("Diag", "Diag", 0, "[FAIL] shell restore: " + str(e), "HIGH")

    def on_photos_rereg(self):
        def run():
            try:
                ps = ("Get-AppxPackage Microsoft.Windows.Photos | "
                      "Foreach-Object {Add-AppxPackage -DisableDevelopmentMode "
                      "-Register \"$($_.InstallLocation)\\AppXManifest.xml\"}")
                r = _run(
                    ["powershell", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                     "-Command", ps], capture_output=True, timeout=120)
                out = (r.stdout + r.stderr).decode("utf-8", "replace")
                lvl = "OK" if r.returncode == 0 else "HIGH"
                emit("Diag", "Diag", 0,
                     "Photos ReReg rc=%d %s" % (r.returncode, out[:400]), lvl)
            except Exception as e:
                emit("Diag", "Diag", 0, "[FAIL] Photos ReReg: " + str(e), "HIGH")
        threading.Thread(target=run, daemon=True).start()

    def on_spi_test(self):
        p = filedialog.askopenfilename(
            title="Wallpaper olarak denenecek JPG",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.bmp"),
                       ("All", "*.*")])
        if not p:
            return
        ok, err = win32_set_wallpaper(p)
        if ok:
            emit("Diag", "Diag", 0,
                 "[OK] SPI_SETDESKWALLPAPER basarili. Windows API saglam, "
                 "sorun uygulamada.", "OK")
            messagebox.showinfo("SPI Test",
                                "Windows API saglam, sorun uygulamada.")
        else:
            emit("Diag", "Diag", 0,
                 "[FAIL] SPI_SETDESKWALLPAPER err=%s" % (err,), "HIGH")
            messagebox.showerror("SPI Test", "Basarisiz. err=" + str(err))

    def on_close(self):
        try:
            self.stop.set()
            if self.hook_collector:
                self.hook_collector.uninstall()
        except Exception:
            pass
        try:
            live_log("=== FINAL: events=%d dropped=%d ===" %
                     (self.events_count, BUS.dropped))
            live_log("=== log closed at " + datetime.now().isoformat() + " ===")
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    startup_log("main() entered")
    admin = is_admin()
    startup_log("IsUserAnAdmin = " + str(admin))
    if not admin:
        try:
            r = tk.Tk(); r.withdraw()
            resp = messagebox.askyesnocancel(
                "Elevation",
                "Yonetici degilsiniz.\n\n"
                "Yes    = yonetici olarak yeniden baslat (UAC)\n"
                "No     = adminsiz devam et (ETW kernel ve WPR calismaz)\n"
                "Cancel = cikis")
            try: r.destroy()
            except Exception: pass
        except Exception:
            resp = False
        if resp is None:
            startup_log("user cancelled elevation")
            return
        if resp:
            ok = relaunch_as_admin()
            startup_log("relaunch = " + str(ok))
            return
        startup_log("continuing without admin")
    root = tk.Tk()
    def _report(et, e, tb):
        _excepthook(et, e, tb)
        try:
            messagebox.showerror("Unhandled",
                                 "".join(traceback.format_exception(et, e, tb))[:2000])
        except Exception:
            pass
    root.report_callback_exception = _report
    app = App(root, admin)
    startup_log("Tk mainloop entering")
    root.mainloop()
    startup_log("Tk mainloop exited")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        _excepthook(*sys.exc_info())
        raise