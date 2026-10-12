#!/usr/bin/env python
# 18.py - Bastard v4 Unified Trace Toolkit
# Buyuk degisiklikler:
#  - RegistryPoller: WMI olmadan saniyede 2 kez registry diff (Photos icin kesin)
#  - FileWatchCollector: %APPDATA%\Themes + Photos LocalState izler
#  - ProcMon: full registry reset, final read AFTER shutdown, dosya boyut tani
#  - WMI registry hatasi gorunur loglandi
#  - ETW mesaji duzeltildi

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, sys, subprocess, queue, winreg, csv
import json, ctypes, atexit
from datetime import datetime, timedelta
from pathlib import Path

HAVE_PSUTIL = HAVE_WMI = HAVE_WIN32 = HAVE_ETW = HAVE_PROCMON_PARSER = False
HAVE_WATCHDOG = False

try:
    import psutil; HAVE_PSUTIL = True
except ImportError: pass
try:
    import pythoncom
    import wmi; HAVE_WMI = True
except ImportError:
    pythoncom = None
try:
    import win32evtlog, win32evtlogutil, win32con, win32api
    import win32security; HAVE_WIN32 = True
except ImportError: pass
try:
    import etw as etw_mod; HAVE_ETW = True
except ImportError: pass
try:
    from procmon_parser import ProcmonLogsReader
    HAVE_PROCMON_PARSER = True
except ImportError: pass
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError: pass

NO_WINDOW = 0x08000000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_STEM = Path(__file__).stem or '18'


# =================================================================
#  ADMIN / ELEVATION
# =================================================================
_shell_execute = ctypes.windll.shell32.ShellExecuteW
_shell_execute.restype = ctypes.c_ssize_t
SW_SHOWNORMAL = 1
SHELL_EXECUTE_ERROR_THRESHOLD = 32


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _request_elevation() -> bool:
    executable = sys.executable
    if getattr(sys, 'frozen', False):
        params = ' '.join(f'"{a}"' for a in sys.argv[1:])
    else:
        script = Path(sys.argv[0]).resolve()
        params = ' '.join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
    ret = _shell_execute(None, 'runas', executable, params or None,
                         str(Path.cwd()), SW_SHOWNORMAL)
    if ret <= SHELL_EXECUTE_ERROR_THRESHOLD:
        raise OSError(f'ShellExecuteW failed with code {ret}')
    return True


def _show_admin_prompt(parent) -> str:
    dialog = tk.Toplevel(parent)
    dialog.title('Administrator Privileges Recommended')
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()

    result = {'value': 'continue'}
    frame = ttk.Frame(dialog, padding=20)
    frame.pack(fill='both', expand=True)
    top = ttk.Frame(frame); top.pack(fill='x')
    tk.Label(top, text='!', font=('Segoe UI', 36),
             foreground='#f0ad4e').pack(side='left', padx=(0, 16))
    tk.Label(top, justify='left', font=('Segoe UI', 10),
        text=('This application may modify system registry keys (e.g., HKLM).\n'
              'Administrator privileges are recommended.\n\n'
              'ETW kernel sessions also require admin rights.\n\n'
              'Run as administrator now?')).pack(side='left')
    btns = ttk.Frame(frame); btns.pack(fill='x', pady=(20, 0))

    def choose(v):
        result['value'] = v; dialog.destroy()

    ttk.Button(btns, text='Run as Administrator',
               command=lambda: choose('elevate')).pack(side='left', padx=4)
    ttk.Button(btns, text='Continue Without',
               command=lambda: choose('continue')).pack(side='left', padx=4)
    ttk.Button(btns, text='Exit',
               command=lambda: choose('exit')).pack(side='right', padx=4)
    dialog.protocol('WM_DELETE_WINDOW', lambda: choose('exit'))
    dialog.update_idletasks()
    w, h = dialog.winfo_width(), dialog.winfo_height()
    sw, sh = dialog.winfo_screenwidth(), dialog.winfo_screenheight()
    dialog.geometry(f'+{(sw - w) // 2}+{(sh - h) // 2}')
    parent.wait_window(dialog)
    return result['value']


# =================================================================
#  YARDIMCILAR
# =================================================================
def find_desktop():
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong),
                        ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort),
                        ("Data4", ctypes.c_ubyte * 8)]
        fid = GUID(0xB4BFCC3A, 0xDB2C, 0x424C,
                   (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9,
                                        0x9A, 0x87, 0xC6, 0x41))
        fn = ctypes.windll.shell32.SHGetKnownFolderPath
        fn.restype = ctypes.c_long
        fn.argtypes = [ctypes.POINTER(GUID), ctypes.c_ulong,
                       ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        p = ctypes.c_wchar_p()
        hr = fn(ctypes.byref(fid), 0, None, ctypes.byref(p))
        if hr == 0 and p.value:
            r = Path(p.value)
            try: ctypes.windll.ole32.CoTaskMemFree(p)
            except Exception: pass
            if r.is_dir(): return r
    except Exception:
        pass
    up = Path(os.environ.get('USERPROFILE', str(Path.home())))
    for c in (up / 'Desktop', up / 'OneDrive' / 'Desktop',
              up / 'OneDrive' / 'Masaüstü', up / 'Masaüstü'):
        if c.is_dir(): return c
    return up

DESKTOP = find_desktop()


def find_procmon():
    cands = []
    for d in (BASE_DIR, str(DESKTOP), os.getcwd(),
              r'C:\Tools', r'C:\Sysinternals'):
        for name in ('Procmon64.exe', 'Procmon.exe',
                     'procmon64.exe', 'procmon.exe'):
            cands.append(os.path.join(d, name))
    for path in os.environ.get('PATH', '').split(os.pathsep):
        if not path: continue
        for name in ('Procmon64.exe', 'Procmon.exe'):
            cands.append(os.path.join(path, name))
    for c in cands:
        if os.path.exists(c): return c
    return None

PROCMON_EXE = find_procmon()


# --- Registry polling hedefleri (Photos Set As icin) ---
REG_POLL_TARGETS = [
    ('HKCU', r'Control Panel\Desktop'),
    ('HKCU', r'Control Panel\Desktop\WindowMetrics'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Lock Screen'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes\CachedFiles'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background'),
]

HIVE_MAP = {'HKCU': winreg.HKEY_CURRENT_USER,
            'HKLM': winreg.HKEY_LOCAL_MACHINE}


# --- File watcher hedefleri ---
def file_watch_targets():
    targets = []
    ad = os.environ.get('APPDATA', '')
    la = os.environ.get('LOCALAPPDATA', '')
    if ad:
        targets.append(os.path.join(ad, 'Microsoft', 'Windows', 'Themes'))
    if la:
        targets.append(os.path.join(la, 'Microsoft', 'Windows', 'Themes'))
        targets.append(os.path.join(la, 'Packages',
                                    'Microsoft.Windows.Photos_8wekyb3d8bbwe'))
        targets.append(os.path.join(la, 'Packages',
                                    'Microsoft.Windows.Photos_8wekyb3d8bbwe',
                                    'LocalState'))
    return [t for t in targets if os.path.isdir(t)]


PROCMON_PATH_KEYWORDS = (
    'wallpaper', 'theme', 'personaliz', 'lockscreen', 'lock screen',
    'transcoded', 'photos', 'runtimebroker', 'immersive',
    'backgrounds', 'control panel\\desktop', 'shell',
)
PROCMON_PROC_HOT = (
    'photos.exe', 'runtimebroker.exe', 'systemsettings.exe',
    'shellexperiencehost.exe', 'dllhost.exe', 'explorer.exe',
    'lockapp.exe', 'backgroundtaskhost.exe', 'applicationframehost.exe',
    'searchhost.exe', 'startmenuexperiencehost.exe',
)


class UEvent:
    __slots__ = ('ts', 'source', 'etype', 'pid', 'details', 'level', 'raw')
    def __init__(self, source, etype, details, pid=None, level='info', raw=None):
        self.ts = datetime.now()
        self.source = source
        self.etype = etype
        self.pid = pid
        self.details = details
        self.level = level
        self.raw = raw
    def to_log_line(self):
        return (f'{self.ts.strftime("%H:%M:%S.%f")[:-3]} '
                f'[{self.source}] [{self.etype}] {self.details}')


# =================================================================
#  0. REGISTRY POLLER (WMI'siz, kesin calisir)
# =================================================================
class RegistryPoller(threading.Thread):
    def __init__(self, emit, interval=0.5):
        super().__init__(daemon=True)
        self.emit = emit
        self.interval = interval
        self.running = False
        self.snapshot = {}

    def _read_all(self):
        out = {}
        for hive_name, base in REG_POLL_TARGETS:
            hive = HIVE_MAP[hive_name]
            for subkey, values in self._read_key_recursive(hive, base, depth=0).items():
                full = f'{hive_name}\\{subkey}'
                for val_name, val in values.items():
                    out[f'{full}\\{val_name}'] = val
        return out

    def _read_key_recursive(self, hive, path, depth):
        result = {}
        if depth > 4:
            return result
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            return result
        try:
            vals = {}
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                    try: vals[name] = str(val)
                    except Exception: vals[name] = repr(val)
                    i += 1
                except OSError:
                    break
            result[path] = vals
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                    result.update(self._read_key_recursive(
                        hive, path + '\\' + sub, depth + 1))
                    i += 1
                except OSError:
                    break
        finally:
            try: winreg.CloseKey(k)
            except Exception: pass
        return result

    def run(self):
        self.snapshot = self._read_all()
        self.emit(UEvent('RegPoll', 'Process',
            f'Registry poller aktif ({len(self.snapshot)} deger, '
            f'her {int(self.interval*1000)}ms diff)', level='info'))
        self.running = True
        while self.running:
            time.sleep(self.interval)
            try:
                cur = self._read_all()
            except Exception as e:
                self.emit(UEvent('RegPoll', 'Error',
                    f'Okuma hatasi: {e}', level='error'))
                continue
            self._diff(self.snapshot, cur)
            self.snapshot = cur

    def _diff(self, old, new):
        for k, v in new.items():
            if k not in old:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[+] {k} = {v}', level='change'))
            elif old[k] != v:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[~] {k}: {old[k]} -> {v}', level='change'))
        for k, v in old.items():
            if k not in new:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[-] {k} silindi (eski: {v})', level='change'))

    def stop(self):
        self.running = False


# =================================================================
#  0b. FILE WATCH (Themes + Photos AppData)
# =================================================================
class FileWatchCollector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.observer = None

    def run(self):
        if not HAVE_WATCHDOG:
            self.emit(UEvent('FileWatch', 'Error',
                'watchdog yok. Kur: pip install watchdog', level='error'))
            return
        targets = file_watch_targets()
        if not targets:
            self.emit(UEvent('FileWatch', 'Process',
                'Izlenebilir klasor bulunamadi', level='info'))
            return

        outer = self
        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory: return
                src = getattr(event, 'src_path', '')
                dst = getattr(event, 'dest_path', '')
                outer.emit(UEvent('FileWatch', 'File',
                    f'{event.event_type}: {src}'
                    f'{(" -> " + dst) if dst else ""}', level='change'))

        self.observer = Observer()
        h = Handler()
        ok = 0
        for t in targets:
            try:
                self.observer.schedule(h, t, recursive=True)
                ok += 1
            except Exception as e:
                self.emit(UEvent('FileWatch', 'Error',
                    f'Schedule hatasi {t}: {e}', level='error'))
        try:
            self.observer.start()
            self.emit(UEvent('FileWatch', 'Process',
                f'File watcher aktif ({ok} klasor)', level='info'))
        except Exception as e:
            self.emit(UEvent('FileWatch', 'Error',
                f'Observer baslatilamadi: {e}', level='error'))
            return

        self.running = True
        while self.running:
            time.sleep(0.5)
        try:
            self.observer.stop()
            self.observer.join(timeout=2)
        except Exception: pass

    def stop(self):
        self.running = False


# =================================================================
#  1. PROCMON (final read AFTER shutdown fix)
# =================================================================
class ProcMonCollector(threading.Thread):
    def __init__(self, emit, base_dir):
        super().__init__(daemon=True)
        self.emit = emit
        self.base_dir = base_dir
        self.running = False
        self.proc = None
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pml_path = os.path.join(
            base_dir, f'{SCRIPT_STEM}_trace_{ts}.pml')
        self.seen_hashes = set()
        self.raw_seen = 0
        self.emitted = 0

    def run(self):
        if not PROCMON_EXE:
            self.emit(UEvent('ProcMon', 'Error',
                'Procmon64.exe bulunamadi.', level='error'))
            return
        if not HAVE_PROCMON_PARSER:
            self.emit(UEvent('ProcMon', 'Error',
                'procmon-parser YOK. Kur: pip install procmon-parser',
                level='error'))

        self._cleanup_old_pmls()
        self._reset_procmon_registry()

        try:
            cmd = [PROCMON_EXE, '/AcceptEula', '/Quiet', '/Minimized',
                   '/BackingFile', self.pml_path]
            self.proc = subprocess.Popen(
                cmd, creationflags=NO_WINDOW,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=self.base_dir)
            self.emit(UEvent('ProcMon', 'Process',
                f'ProcMon baslatildi -> {os.path.basename(self.pml_path)}',
                level='info'))
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error',
                f'ProcMon baslatilamadi: {e}', level='error'))
            return

        # 2 saniye sonra dosya olustu mu kontrol et
        time.sleep(2.0)
        if os.path.exists(self.pml_path):
            sz = os.path.getsize(self.pml_path)
            self.emit(UEvent('ProcMon', 'Process',
                f'PML olustu, boyut={sz}B', level='info'))
        else:
            self.emit(UEvent('ProcMon', 'Error',
                f'PML olusmadi! ProcMon arka planda baslamadi olabilir. '
                f'Yol: {self.pml_path}', level='error'))

        self.running = True
        while self.running:
            for _ in range(8):
                if not self.running: break
                time.sleep(0.25)
            if not self.running: break
            try:
                self._read_new_events()
            except Exception as e:
                self.emit(UEvent('ProcMon', 'Error',
                    f'PML read: {e}', level='error'))

        # >>> FIX: once ProcMon'u kapat, dosya tam yazilsin, SONRA son okuma <<<
        self._shutdown_procmon()
        time.sleep(1.5)
        try:
            self._read_new_events()
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error',
                f'Son okuma: {e}', level='error'))

        if self.raw_seen == 0:
            if os.path.exists(self.pml_path):
                sz = os.path.getsize(self.pml_path)
                self.emit(UEvent('ProcMon', 'Error',
                    f'ProcMon 0 event yakaladi ama PML {sz}B. '
                    f'ProcMon GUI filtresi aktif olabilir; '
                    f'registry temizlendi ama ProcMon acikken elle filtre koymussan '
                    f'bir sonraki trace temiz olur.', level='error'))
            else:
                self.emit(UEvent('ProcMon', 'Error',
                    'PML dosyasi hic olusmadi', level='error'))

        self.emit(UEvent('ProcMon', 'Process',
            f'ProcMon durdu. {self.raw_seen} raw -> {self.emitted} filtrelenmis',
            level='info'))

    def _cleanup_old_pmls(self):
        try:
            for f in os.listdir(self.base_dir):
                fl = f.lower()
                if fl.endswith('.pml') and (
                        fl.startswith(f'{SCRIPT_STEM.lower()}_trace_')
                        or fl.startswith('trace_')
                        or fl.startswith('bastard_trace_')
                        or fl.startswith('deepseek_')):
                    try: os.remove(os.path.join(self.base_dir, f))
                    except Exception: pass
        except Exception: pass

    def _reset_procmon_registry(self):
        """ProcMon registry anahtarini TAMAMEN sil. Boylece son filtre
        ve son backing file referansi temizlenir."""
        try:
            subprocess.run(
                ['reg', 'delete',
                 r'HKCU\Software\Sysinternals\Process Monitor', '/f'],
                capture_output=True, creationflags=NO_WINDOW, timeout=5)
            self.emit(UEvent('ProcMon', 'Process',
                'ProcMon registry ayarlari sifirlandi (filtre temiz)',
                level='info'))
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error',
                f'ProcMon registry reset hatasi: {e}', level='error'))

    def _shutdown_procmon(self):
        if not self.proc: return
        try:
            if self.proc.poll() is None:
                subprocess.run(['taskkill', '/PID', str(self.proc.pid)],
                               capture_output=True, creationflags=NO_WINDOW,
                               timeout=5)
                try: self.proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    subprocess.run(
                        ['taskkill', '/F', '/PID', str(self.proc.pid)],
                        capture_output=True, creationflags=NO_WINDOW,
                        timeout=5)
        except Exception: pass

    def _read_new_events(self):
        if not os.path.exists(self.pml_path):
            return
        try:
            with open(self.pml_path, 'rb') as f:
                reader = ProcmonLogsReader(f)
                for ev in reader:
                    op = getattr(ev, 'operation', None) or ''
                    path = getattr(ev, 'path', None) or ''
                    res = getattr(ev, 'result', None) or ''
                    pid = getattr(ev, 'pid', None)
                    pname = getattr(ev, 'process_name', '?') or '?'
                    tod = getattr(ev, 'time_of_day', None)
                    key = (pname, pid, op, str(path), res, str(tod))
                    h = hash(key)
                    if h in self.seen_hashes: continue
                    self.seen_hashes.add(h)
                    self.raw_seen += 1

                    denied = self._is_denied(res)
                    path_low = str(path).lower()
                    pname_low = pname.lower()
                    op_upper = op.upper()

                    is_reg_change = ('REG' in op_upper and any(
                        k in op_upper for k in
                        ('SET', 'CREATE', 'DELETE', 'RENAME')))
                    is_hot_proc = pname_low in PROCMON_PROC_HOT
                    is_hot_path = any(kw in path_low
                                      for kw in PROCMON_PATH_KEYWORDS)

                    if not denied and not (is_hot_proc and is_reg_change) \
                            and not is_hot_path:
                        continue

                    self.emitted += 1
                    etype = self._classify_op(op)

                    if denied:
                        self.emit(UEvent('ProcMon', etype,
                            f'{op} {path} -> {res} (PID={pid} {pname})',
                            pid=pid, level='error'))
                    elif etype == 'Registry' and is_reg_change:
                        self.emit(UEvent('ProcMon', 'Registry',
                            f'{op} {path} -> {res} ({pname})',
                            pid=pid, level='change'))
                    elif is_hot_path:
                        self.emit(UEvent('ProcMon', etype,
                            f'{op} {path} -> {res} ({pname})',
                            pid=pid, level='change'))
        except Exception:
            pass

    @staticmethod
    def _is_denied(result):
        if not result: return False
        r = str(result).lower()
        return ('access denied' in r or 'erişim engellendi' in r
                or 'privilege not held' in r or 'access is denied' in r)

    @staticmethod
    def _classify_op(op):
        if not op: return 'Unknown'
        o = str(op).upper()
        if 'REG' in o: return 'Registry'
        if any(k in o for k in ('CREATE', 'WRITE', 'READ', 'SETINFO',
                                'QUERY', 'CLOSE', 'DELETE', 'RENAME',
                                'FILE')):
            return 'File'
        if 'TCP' in o or 'UDP' in o or 'SEND' in o or 'RECEIVE' in o:
            return 'Network'
        if 'PROCESS' in o or 'THREAD' in o:
            return 'Process'
        return 'Other'

    def stop(self):
        self.running = False


# =================================================================
#  2. ETW
# =================================================================
class ETWCollector(threading.Thread):
    KERNEL_REGISTRY = '{70EB4F03-C1DE-4F73-A051-33D13D541355}'
    KERNEL_FILE = '{EDD08927-9CC4-4E65-B970-C2560FB5C289}'
    SHELL_CORE = '{30336ED4-E327-447C-9DE0-51B2E6059F02}'
    IMMERSIVE_SHELL = '{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}'

    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.sessions = []
        self.event_count = 0

    def run(self):
        if not HAVE_ETW:
            self.emit(UEvent('ETW', 'Error',
                'pywintrace yok. Kur: pip install pywintrace',
                level='error'))
            return
        if not is_admin():
            self.emit(UEvent('ETW', 'Error',
                'ETW icin ADMIN gerekli. Yonetici olarak baslat.',
                level='error'))
            return
        providers = []
        for name, guid in (('Kernel-Registry', self.KERNEL_REGISTRY),
                           ('Kernel-File', self.KERNEL_FILE),
                           ('Shell-Core', self.SHELL_CORE),
                           ('Immersive-Shell', self.IMMERSIVE_SHELL)):
            try:
                providers.append(etw_mod.ProviderInfo(
                    name, etw_mod.GUID(guid)))
            except Exception as e:
                self.emit(UEvent('ETW', 'Error',
                    f'ProviderInfo {name}: {e}', level='error'))
        if not providers: return

        self.emit(UEvent('ETW', 'Process',
            f'{len(providers)} provider deneniyor...', level='info'))
        try:
            job = etw_mod.ETW(providers=providers,
                              event_callback=self._on_etw_event)
            job.start()
            self.sessions.append(job)
            self.emit(UEvent('ETW', 'Process',
                'ETW session basladi (event bekleniyor...)', level='info'))
        except Exception as e:
            self.emit(UEvent('ETW', 'Error',
                f'ETW start hatasi: {e}', level='error'))
            return

        self.running = True
        last_report = time.time()
        while self.running:
            time.sleep(0.5)
            now = time.time()
            if now - last_report > 15:
                last_report = now
                if self.event_count == 0:
                    self.emit(UEvent('ETW', 'Process',
                        'ETW 15 sn\'dir event almiyor. '
                        'Windows 11\'de bazi kernel provider\'lari '
                        'artik desteklenmiyor olabilir. '
                        'RegPoll + FileWatch devrede.', level='info'))
        for s in self.sessions:
            try: s.stop()
            except Exception: pass
        self.emit(UEvent('ETW', 'Process',
            f'ETW kapandi. Toplam {self.event_count} event.',
            level='info'))

    def _on_etw_event(self, event):
        try:
            provider = getattr(event, 'provider_name', '?')
            eid = getattr(event, 'event_id', None)
            pid = getattr(event, 'process_id', None)
            payload = getattr(event, 'payload', None)
            parts = []
            if payload:
                if isinstance(payload, dict):
                    for k, v in list(payload.items())[:6]:
                        if v is not None and str(v).strip():
                            parts.append(f'{k}={v}')
                else:
                    s = str(payload)
                    parts.append(s[:300] + ('...' if len(s) > 300 else ''))
            detail = f'[{provider}] EID={eid} ' + ' | '.join(parts)
            low = detail.lower()
            if ('denied' in low or 'erişim engellendi' in low
                    or '0x80070005' in low or 'access_denied' in low):
                level = 'error'
            elif eid in (1, 2, 3, 11, 12, 13):
                level = 'change'
            else:
                level = 'info'
            if level == 'info' and not any(kw in low for kw in
                    ('wallpaper', 'theme', 'photos', 'personaliz',
                     'lockscreen', 'transcoded')):
                return
            self.event_count += 1
            etype = 'Registry' if 'registry' in str(provider).lower() else 'File'
            self.emit(UEvent('ETW', etype, detail, pid=pid, level=level))
        except Exception:
            pass

    def stop(self):
        self.running = False


# =================================================================
#  3. WMI
# =================================================================
class WMICollector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.watchers = []

    def run(self):
        if not HAVE_WMI:
            self.emit(UEvent('WMI', 'Error',
                'wmi yok. Kur: pip install wmi pywin32', level='error'))
            return
        try: pythoncom.CoInitialize()
        except Exception as e:
            self.emit(UEvent('WMI', 'Error',
                f'CoInitialize: {e}', level='error'))
            return
        try:
            try:
                c = wmi.WMI()
            except Exception as e:
                self.emit(UEvent('WMI', 'Error',
                    f'WMI baglanamadi: {e}', level='error'))
                return

            try:
                pw = c.Win32_Process.watch_for('creation')
                self.watchers.append(('process', pw))
                self.emit(UEvent('WMI', 'Process',
                    'Process creation watcher aktif', level='info'))
            except Exception as e:
                self.emit(UEvent('WMI', 'Error',
                    f'Process watcher: {e}', level='error'))

            self.running = True
            for kind, w in self.watchers:
                threading.Thread(target=self._watch_loop,
                                 args=(kind, w), daemon=True).start()
            while self.running:
                time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def _watch_loop(self, kind, watcher):
        try: pythoncom.CoInitialize()
        except Exception: pass
        try:
            while self.running:
                try:
                    ev = watcher(timeout_ms=3000)
                    if kind == 'process':
                        pid = getattr(ev, 'ProcessId', None)
                        name = getattr(ev, 'Name', '?')
                        cmd = getattr(ev, 'CommandLine', '') or ''
                        cl = cmd.lower()
                        nl = name.lower()
                        if nl in ('photos.exe', 'runtimebroker.exe',
                                  'dllhost.exe', 'systemsettings.exe',
                                  'explorer.exe') or any(
                                k in cl for k in ('wallpaper', 'theme',
                                                  'photos', 'lockscreen')):
                            self.emit(UEvent('WMI', 'Process',
                                f'Yeni process: {name} PID={pid} '
                                f'{cmd[:200]}', pid=pid, level='info'))
                except Exception:
                    time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def stop(self):
        self.running = False


# =================================================================
#  4. PSUTIL
# =================================================================
class PSUtilCollector(threading.Thread):
    TARGETS = ('photos.exe', 'runtimebroker.exe', 'dllhost.exe',
               'shellexperiencehost.exe', 'explorer.exe', 'sihost.exe',
               'startmenuexperiencehost.exe', 'searchhost.exe',
               'backgroundtaskhost.exe', 'applicationframehost.exe',
               'lockapp.exe', 'systemsettings.exe')
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.seen = set()

    def run(self):
        if not HAVE_PSUTIL:
            self.emit(UEvent('psutil', 'Error', 'psutil yok.',
                             level='error'))
            return
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if (p.info.get('name') or '').lower() in self.TARGETS:
                    self.seen.add(p.pid)
            except Exception: pass
        self.running = True
        last_status = 0
        while self.running:
            time.sleep(0.35)
            try:
                for p in psutil.process_iter(
                        ['pid', 'name', 'exe', 'cmdline', 'ppid']):
                    if p.pid in self.seen: continue
                    self.seen.add(p.pid)
                    try:
                        n = (p.info.get('name') or '').lower()
                        cmd = ' '.join(p.info.get('cmdline') or []) \
                              or (p.info.get('exe') or '')
                        if n in self.TARGETS:
                            self.emit(UEvent('psutil', 'Process',
                                f'YENI: {p.info["name"]} PID={p.pid} '
                                f'PPID={p.info.get("ppid")} {cmd[:200]}',
                                pid=p.pid, level='info'))
                    except Exception: pass
            except Exception: pass
            if time.time() - last_status > 8:
                last_status = time.time()
                for p in psutil.process_iter(
                        ['pid', 'name', 'status']):
                    try:
                        if (p.info.get('name') or '').lower() == 'photos.exe':
                            self.emit(UEvent('psutil', 'Process',
                                f'Photos durum: PID={p.pid} '
                                f'status={p.info.get("status")}',
                                pid=p.pid, level='info'))
                    except Exception: pass

    def stop(self):
        self.running = False


# =================================================================
#  5. WIN32 (EventLog)
# =================================================================
class Win32Collector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False

    def run(self):
        self.running = True
        if HAVE_WIN32:
            threading.Thread(target=self._eventlog_loop, daemon=True).start()
        else:
            self.emit(UEvent('Win32', 'Error',
                'pywin32 yok. Kur: pip install pywin32', level='error'))
        while self.running:
            time.sleep(0.5)

    def _eventlog_loop(self):
        cutoff = datetime.now() - timedelta(seconds=60)
        channels = ('Application', 'System')
        last_records = {}
        backfilled = 0

        for ch in channels:
            h = None
            try:
                h = win32evtlog.OpenEventLog(None, ch)
                flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                         win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                evs = win32evtlog.ReadEventLog(h, flags, 0)
                if evs:
                    last_records[ch] = evs[0].RecordNumber
                for ev in evs[:200]:
                    try:
                        ts = ev.TimeGenerated
                        try: ts = ts.timetuple()
                        except Exception: pass
                        evt_dt = datetime(*ts[:6]) if isinstance(ts, tuple) \
                                 else datetime.now()
                        if evt_dt < cutoff: break
                        if ev.EventType not in (
                                win32con.EVENTLOG_ERROR_TYPE,
                                win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = ('error' if ev.EventType ==
                               win32con.EVENTLOG_ERROR_TYPE else 'warn')
                        try:
                            msg = ' | '.join(ev.StringInserts) \
                                  if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 350: msg = msg[:350] + '...'
                        low = msg.lower()
                        interesting = any(k in low for k in
                            ('photos', 'wallpaper', 'theme', 'runtimebroker',
                             '0x80070005', 'access denied', 'immersion',
                             'shell', 'start menu', 'dwm'))
                        if interesting:
                            self.emit(UEvent('EvtLog', 'Log',
                                f'[BACKFILL {ch}] {ev.SourceName} '
                                f'ID={ev.EventID & 0xFFFF} {msg}',
                                level=lvl))
                            backfilled += 1
                    except Exception: pass
            except Exception: pass
            finally:
                if h is not None:
                    try: win32evtlog.CloseEventLog(h)
                    except Exception: pass

        if backfilled:
            self.emit(UEvent('Win32', 'Log',
                f'Backfill: son 60 sn\'de {backfilled} ilgili kayit.',
                level='info'))
        else:
            self.emit(UEvent('Win32', 'Log',
                'Backfill: son 60 sn\'de ilgili kayit yok (temiz).',
                level='info'))
        self.emit(UEvent('Win32', 'Log',
            'EventLog takibi basladi (canli).', level='info'))

        while self.running:
            time.sleep(2.0)
            for ch in channels:
                h = None
                try:
                    h = win32evtlog.OpenEventLog(None, ch)
                    flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
                             win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                    last = last_records.get(ch, 0)
                    evs = win32evtlog.ReadEventLog(h, flags, 0)
                    if not evs: continue
                    maxrec = last
                    for ev in evs:
                        if ev.RecordNumber <= last: continue
                        maxrec = max(maxrec, ev.RecordNumber)
                        if ev.EventType not in (
                                win32con.EVENTLOG_ERROR_TYPE,
                                win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = ('error' if ev.EventType ==
                               win32con.EVENTLOG_ERROR_TYPE else 'warn')
                        try:
                            msg = ' | '.join(ev.StringInserts) \
                                  if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 400: msg = msg[:400] + '...'
                        self.emit(UEvent('EvtLog', 'Log',
                            f'[{ch}] {ev.SourceName} '
                            f'ID={ev.EventID & 0xFFFF} {msg}',
                            level=lvl))
                    last_records[ch] = maxrec
                except Exception: pass
                finally:
                    if h is not None:
                        try: win32evtlog.CloseEventLog(h)
                        except Exception: pass

    def stop(self):
        self.running = False


# =================================================================
#  6. UNIFIED TRACER
# =================================================================
class UnifiedTracer:
    def __init__(self, emit):
        self.emit = emit
        self.collectors = []
        self.running = False
        self.start_time = None

    def start(self):
        if self.running: return
        self.running = True
        self.start_time = datetime.now()

        admin = is_admin()
        missing = []
        if not HAVE_PSUTIL: missing.append('psutil')
        if not HAVE_WMI: missing.append('wmi')
        if not HAVE_WIN32: missing.append('pywin32')
        if not HAVE_ETW: missing.append('pywintrace')
        if not HAVE_PROCMON_PARSER: missing.append('procmon-parser')
        if not HAVE_WATCHDOG: missing.append('watchdog')

        self.emit(UEvent('System', 'Marker',
            f'=== TRACE BASLADI === {self.start_time}', level='error'))
        self.emit(UEvent('System', 'Process',
            f'Admin: {"EVET" if admin else "HAYIR"}', level='info'))
        self.emit(UEvent('System', 'Process',
            f'Desktop: {DESKTOP}', level='info'))
        self.emit(UEvent('System', 'Process',
            f'BASE_DIR: {BASE_DIR}', level='info'))
        if PROCMON_EXE:
            self.emit(UEvent('System', 'Process',
                f'ProcMon: {PROCMON_EXE}', level='info'))
        if missing:
            self.emit(UEvent('System', 'Error',
                f'Eksik pip: {", ".join(missing)}', level='error'))

        self.emit(UEvent('System', 'Marker',
            '>>> SIMDI: Photos\'ta Set As yap, hata cikana kadar bekle. '
            'En az 20 saniye trace et.', level='error'))

        collectors = []
        # RegPoll ve FileWatch her zaman aktif, WMI/ETW'ye bagimli degil
        collectors.append(RegistryPoller(self.emit))
        if HAVE_WATCHDOG:
            collectors.append(FileWatchCollector(self.emit))
        if PROCMON_EXE:
            collectors.append(ProcMonCollector(self.emit, BASE_DIR))
        if HAVE_ETW:
            collectors.append(ETWCollector(self.emit))
        if HAVE_WMI:
            collectors.append(WMICollector(self.emit))
        if HAVE_PSUTIL:
            collectors.append(PSUtilCollector(self.emit))
        if HAVE_WIN32:
            collectors.append(Win32Collector(self.emit))

        self.collectors = collectors
        for c in collectors: c.start()
        self.emit(UEvent('System', 'Process',
            f'{len(collectors)} collector aktif.', level='info'))

    def stop(self):
        if not self.running: return
        self.running = False
        self.emit(UEvent('System', 'Marker',
            '>>> TRACE DURDURULUYOR (5-8 sn)...', level='error'))
        for c in self.collectors:
            try: c.stop()
            except Exception: pass
        for c in self.collectors:
            try:
                if c.is_alive(): c.join(timeout=8)
            except Exception: pass
        self.emit(UEvent('System', 'Marker',
            f'=== TRACE BITTI === sure: '
            f'{datetime.now() - self.start_time}', level='error'))


# =================================================================
#  GUI
# =================================================================
class App:
    SOURCES = {
        'RegPoll':   {'label': 'RegPoll', 'color': '#f0c060'},
        'FileWatch': {'label': 'FileWatch', 'color': '#a4e400'},
        'ProcMon':   {'label': 'ProcMon', 'color': '#ff9f43'},
        'ETW':       {'label': 'ETW', 'color': '#54a0ff'},
        'WMI':       {'label': 'WMI', 'color': '#5f27cd'},
        'psutil':    {'label': 'psutil', 'color': '#10ac84'},
        'Win32':     {'label': 'Win32', 'color': '#c8d6e5'},
        'EvtLog':    {'label': 'EvtLog', 'color': '#ee5253'},
        'System':    {'label': 'System', 'color': '#8395a7'},
    }
    ETYPES = {
        'Process': '#7ec8ff', 'Registry': '#f0c060', 'File': '#a4e400',
        'Network': '#ff9ff3', 'Hook': '#c8d6e5', 'Log': '#ff6b6b',
        'Error': '#ff6b6b', 'Marker': '#ff00ff', 'Unknown': '#dcdcdc',
    }

    def __init__(self, root):
        self.root = root
        root.title(f'Bastard v4 ({SCRIPT_STEM})')
        root.geometry('1440x900')

        self.queue = queue.Queue()
        self.tracer = UnifiedTracer(self._emit_u)
        self.log = []
        self.live_log_fh = None
        self.live_log_path = None
        self.trace_start_ts = None

        top = ttk.Frame(root, padding=6); top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='> Trace Baslat',
                                    command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='[] Durdur',
                                   command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        self.btn_mark = ttk.Button(top, text='(o) MARKER Ekle',
                                   command=self.mark, state='disabled')
        self.btn_mark.pack(side='left', padx=4)
        ttk.Button(top, text='On Kontrol',
                   command=self.precheck).pack(side='left', padx=4)
        ttk.Button(top, text='Bagimliliklari Kur',
                   command=self.install_deps).pack(side='left', padx=4)
        ttk.Button(top, text='Log Klasoru',
                   command=self.open_log_folder).pack(side='left', padx=4)
        ttk.Button(top, text='JSON',
                   command=self.save_json).pack(side='left', padx=4)
        ttk.Button(top, text='CSV',
                   command=self.save_csv).pack(side='left', padx=4)
        ttk.Button(top, text='Temizle',
                   command=self.clear).pack(side='left', padx=4)

        self.status = ttk.Label(top, text=f'Desktop: {DESKTOP}',
                                foreground='gray')
        self.status.pack(side='right')

        if not is_admin():
            tk.Label(root,
                text='! Yonetici degilsin. ETW BOS KALACAK.',
                fg='#ff4757', font=('Segoe UI', 9, 'bold')).pack(
                    fill='x', padx=6)

        stat = ttk.Frame(root, padding=(6, 0)); stat.pack(fill='x')
        self.collector_labels = {}
        for src, meta in self.SOURCES.items():
            if src == 'System': continue
            lbl = tk.Label(stat, text=f'* {meta["label"]}', fg='gray',
                           font=('Segoe UI', 8, 'bold'))
            lbl.pack(side='left', padx=4)
            self.collector_labels[src] = lbl
        self.timer_lbl = ttk.Label(stat, text='', foreground='#0f0',
                                   font=('Consolas', 10, 'bold'))
        self.timer_lbl.pack(side='right', padx=8)
        self.log_path_lbl = ttk.Label(stat, text='', foreground='#666')
        self.log_path_lbl.pack(side='right')

        guide = ttk.LabelFrame(root, text='NASIL KULLANILIR', padding=4)
        guide.pack(fill='x', padx=6, pady=(4, 0))
        ttk.Label(guide,
            text='1) Trace Baslat   '
                 '2) Photos\'ta Set As yap   '
                 '3) MARKER Ekle   '
                 '4) En az 20 sn bekle   '
                 '5) Durdur',
            foreground='#c8d6e5').pack(anchor='w')

        filt = ttk.LabelFrame(root, text='Filtre', padding=6)
        filt.pack(fill='x', padx=6, pady=(4, 0))
        self.f_sources = {}
        for src, meta in self.SOURCES.items():
            var = tk.BooleanVar(value=True)
            self.f_sources[src] = var
            ttk.Checkbutton(filt, text=meta['label'], variable=var,
                            command=self.refilter).pack(side='left', padx=2)
        ttk.Separator(filt, orient='vertical').pack(side='left',
                                                    fill='y', padx=8)
        self.f_err_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text='Sadece Hata', variable=self.f_err_only,
                        command=self.refilter).pack(side='left', padx=2)
        ttk.Label(filt, text='Ara:').pack(side='left', padx=(8, 0))
        self.f_search = tk.StringVar()
        ent = ttk.Entry(filt, textvariable=self.f_search, width=24)
        ent.pack(side='left', padx=4)
        ent.bind('<KeyRelease>', lambda e: self.refilter())

        wrap = ttk.Frame(root); wrap.pack(fill='both', expand=True,
                                          padx=6, pady=6)
        self.txt = scrolledtext.ScrolledText(
            wrap, wrap='none', font=('Consolas', 9),
            bg='#0d0d12', fg='#dcdcdc', insertbackground='white')
        self.txt.pack(fill='both', expand=True)
        for src, meta in self.SOURCES.items():
            self.txt.tag_config(f'src_{src}', foreground=meta['color'])
        for et, col in self.ETYPES.items():
            self.txt.tag_config(f'type_{et}', foreground=col)
        self.txt.tag_config('error', foreground='#ff4757',
                            font=('Consolas', 9, 'bold'))
        self.txt.tag_config('warn', foreground='#ffa502')
        self.txt.tag_config('change', foreground='#f0c060')
        self.txt.tag_config('info', foreground='#a4b0be')
        self.txt.tag_config('marker', foreground='#ff00ff',
                            font=('Consolas', 10, 'bold'))

        root.protocol('WM_DELETE_WINDOW', self._on_close)
        atexit.register(self._close_logfile)
        root.after(60, self._drain)
        root.after(500, self._tick)

    def _tick(self):
        if self.trace_start_ts:
            elapsed = datetime.now() - self.trace_start_ts
            self.timer_lbl.config(
                text=f'[T] {int(elapsed.total_seconds())} sn')
        else:
            self.timer_lbl.config(text='')
        self.root.after(500, self._tick)

    def _open_logfile(self):
        self._close_logfile()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.live_log_path = DESKTOP / f'{SCRIPT_STEM}_{ts}.log'
        try:
            self.live_log_fh = open(self.live_log_path, 'w', encoding='utf-8')
            self.live_log_fh.write(
                f'# Bastard v4 ({SCRIPT_STEM}) - {datetime.now()}\n'
                f'# Log: {self.live_log_path}\n'
                f'# Admin: {is_admin()}\n'
                f'# Desktop: {DESKTOP}\n'
                f'# BASE_DIR: {BASE_DIR}\n')
            self.live_log_fh.flush()
            self.log_path_lbl.config(text=f'Log: {self.live_log_path.name}')
        except Exception as e:
            messagebox.showerror('Log acilamadi',
                                 f'{self.live_log_path}\n{e}')
            self.live_log_fh = None

    def _close_logfile(self):
        if self.live_log_fh:
            try:
                self.live_log_fh.write(f'# KAPANDI: {datetime.now()}\n')
                self.live_log_fh.flush()
                self.live_log_fh.close()
            except Exception: pass
            self.live_log_fh = None

    def _write_live(self, uevent):
        if not self.live_log_fh: return
        try:
            self.live_log_fh.write(uevent.to_log_line() + '\n')
            self.live_log_fh.flush()
        except Exception: pass

    def _emit_u(self, uevent):
        self.queue.put(uevent)

    def _drain(self):
        try:
            while True:
                ev = self.queue.get_nowait()
                self.log.append(ev)
                self._write_live(ev)
                if self._passes(ev): self._write_event(ev)
                if ev.source in self.collector_labels and ev.etype != 'Error':
                    self.collector_labels[ev.source].config(fg='green')
        except queue.Empty:
            pass
        self.root.after(60, self._drain)

    def _passes(self, ev):
        v = self.f_sources.get(ev.source)
        if v is not None and not v.get(): return False
        if self.f_err_only.get() and ev.level not in ('error', 'warn'):
            return False
        q = self.f_search.get().lower()
        if q and q not in ev.details.lower(): return False
        return True

    def _write_event(self, ev):
        ts = ev.ts.strftime('%H:%M:%S.%f')[:-3]
        src = f'[{ev.source}]'
        et = f'[{ev.etype}]'
        if ev.etype == 'Marker':
            tag = 'marker'
        else:
            tag = ('error' if ev.level == 'error' else
                   'warn' if ev.level == 'warn' else
                   'change' if ev.level == 'change' else 'info')
        self.txt.insert('end', f'{ts} ', 'info')
        self.txt.insert('end', f'{src:<11} ', f'src_{ev.source}')
        self.txt.insert('end', f'{et:<10} ', f'type_{ev.etype}')
        self.txt.insert('end', f'{ev.details}\n', tag)
        self.txt.see('end')

    def refilter(self):
        self.txt.delete('1.0', 'end')
        for ev in self.log:
            if self._passes(ev): self._write_event(ev)

    def start(self):
        self._open_logfile()
        self.trace_start_ts = datetime.now()
        threading.Thread(target=self.tracer.start, daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_mark.config(state='normal')
        messagebox.showinfo('Bastard',
            'Trace basladi.\n\n'
            '1) Photos ac, Set As yap\n'
            '2) Hata cikmasini bekle\n'
            '3) MARKER Ekle\n'
            '4) EN AZ 20 SANIYE bekle\n'
            '5) Durdur\n')

    def mark(self):
        self._emit_u(UEvent('System', 'Marker',
            '>>> KULLANICI MARKER: Set As bu anda denendi <<<',
            level='error'))

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.btn_mark.config(state='disabled')
        self.root.after(10000, self._close_logfile)
        self.trace_start_ts = None

    def _on_close(self):
        try: self.tracer.stop()
        except Exception: pass
        time.sleep(0.5)
        self._close_logfile()
        self.root.destroy()

    def precheck(self):
        threading.Thread(target=self._precheck_worker, daemon=True).start()

    def _precheck_worker(self):
        def e(d): self._emit_u(UEvent('System', 'Error', d, level='error'))
        def i(d): self._emit_u(UEvent('System', 'Process', d, level='info'))
        i('===== ON KONTROL v4 =====')
        i(f'Admin: {"EVET" if is_admin() else "HAYIR"}')
        i(f'Desktop: {DESKTOP}')
        i(f'BASE_DIR: {BASE_DIR}')
        if PROCMON_EXE: i(f'ProcMon: {PROCMON_EXE}')
        else: e('ProcMon: YOK')
        for name, ok in (('psutil', HAVE_PSUTIL), ('wmi', HAVE_WMI),
                         ('pywin32', HAVE_WIN32), ('pywintrace', HAVE_ETW),
                         ('procmon-parser', HAVE_PROCMON_PARSER),
                         ('watchdog', HAVE_WATCHDOG)):
            if ok: i(f'{name}: OK')
            else: e(f'{name}: YOK')

        i('[FileWatch hedefleri]')
        for t in file_watch_targets():
            i(f'  {t}')

        pol = [
            ('HKCU',
             r'Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop',
             'NoChangingWallPaper'),
            ('HKCU',
             r'Software\Microsoft\Windows\CurrentVersion\Policies\System',
             'Wallpaper'),
            ('HKCU',
             r'Software\Policies\Microsoft\Windows\Personalization',
             'NoChangingWallPaper'),
            ('HKCU',
             r'Software\Policies\Microsoft\Windows\Personalization',
             'NoChangingLockScreen'),
            ('HKLM',
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
             'Wallpaper'),
            ('HKLM',
             r'SOFTWARE\Policies\Microsoft\Windows\Personalization',
             'NoChangingWallPaper'),
            ('HKLM',
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP',
             'LockScreenImagePath'),
            ('HKLM',
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP',
             'DesktopImagePath'),
            ('HKCU',
             r'Software\Microsoft\Windows\CurrentVersion\Explorer',
             'NoSaveSettings'),
        ]
        i('[Policy]')
        found = False
        for hive, path, name in pol:
            try:
                k = winreg.OpenKey(HIVE_MAP[hive], path)
                v, _ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                e(f'  >> POLITIKA: {hive}\\{path}\\{name} = {v}')
                found = True
            except (FileNotFoundError, OSError): pass
        if not found: i('  Politika yok (iyi)')

        i('[Servisler]')
        if HAVE_PSUTIL:
            for svc in ('Themes', 'AppXSvc', 'ClipSVC', 'StateRepository',
                        'TokenBroker', 'Dwm', 'UxSms', 'ShellHWDetection'):
                try:
                    s = psutil.win_service_get(svc); d = s.as_dict()
                    if d.get('status') != 'running' or \
                            d.get('start_type') == 'disabled':
                        e(f'  >> SORUNLU: {svc} status={d.get("status")} '
                          f'start={d.get("start_type")}')
                    else: i(f'  OK: {svc}')
                except Exception as ex:
                    e(f'  >> Servis yok: {svc} ({ex})')

        i('[TranscodedWallpaper]')
        ad = os.environ.get('APPDATA', '')
        wp = os.path.join(ad, 'Microsoft', 'Windows', 'Themes',
                          'TranscodedWallpaper')
        if os.path.exists(wp):
            try:
                with open(wp, 'ab'): pass
                i('  OK yazilabilir')
            except Exception as ex:
                e(f'  >> YAZILAMAZ: {ex}')
        else:
            i('  Yok (normal)')
        i('===== BITTI =====')

    def install_deps(self):
        if not messagebox.askyesno('Bagimlilik',
                'psutil, wmi, pywin32, pywintrace, procmon-parser, '
                'watchdog kurulacak.\nDevam?'):
            return
        def _run():
            try:
                p = subprocess.Popen(
                    [sys.executable, '-m', 'pip', 'install', '--upgrade',
                     'psutil', 'wmi', 'pywin32', 'pywintrace',
                     'procmon-parser', 'watchdog'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    creationflags=NO_WINDOW, text=True)
                for line in p.stdout:
                    self._emit_u(UEvent('System', 'Process',
                        f'[pip] {line.rstrip()}', level='info'))
                p.wait()
                self._emit_u(UEvent('System', 'Process',
                    'Kurulum bitti. Yeniden baslat.', level='info'))
            except Exception as ex:
                self._emit_u(UEvent('System', 'Error',
                    f'pip: {ex}', level='error'))
        threading.Thread(target=_run, daemon=True).start()

    def open_log_folder(self):
        try: os.startfile(str(DESKTOP))
        except Exception as ex: messagebox.showerror('Hata', str(ex))

    def save_json(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.json', initialdir=str(DESKTOP),
            filetypes=[('JSON', '*.json')])
        if not p: return
        data = [{'ts': ev.ts.isoformat(), 'source': ev.source,
                 'type': ev.etype, 'pid': ev.pid,
                 'level': ev.level, 'details': ev.details}
                for ev in self.log]
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        messagebox.showinfo('Kaydedildi', f'{len(data)} event')

    def save_csv(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.csv', initialdir=str(DESKTOP),
            filetypes=[('CSV', '*.csv')])
        if not p: return
        with open(p, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['timestamp', 'source', 'type', 'pid',
                        'level', 'details'])
            for ev in self.log:
                w.writerow([ev.ts.isoformat(), ev.source, ev.etype,
                            ev.pid or '', ev.level, ev.details])
        messagebox.showinfo('Kaydedildi', f'{len(self.log)} event')

    def clear(self):
        self.log.clear()
        self.txt.delete('1.0', 'end')


def main():
    root = tk.Tk()
    root.withdraw()

    if not is_admin():
        choice = _show_admin_prompt(root)
        if choice == 'elevate':
            try:
                _request_elevation()
                root.destroy()
                return 0
            except OSError as exc:
                messagebox.showerror(
                    'Elevation Failed',
                    f'{exc}\n\nYetkisiz devam ediliyor.')
        elif choice == 'exit':
            root.destroy()
            return 0

    try:
        root.call('tk', 'scaling', 1.1)
    except Exception: pass
    root.deiconify()
    App(root)
    root.mainloop()
    return 0


if __name__ == '__main__':
    main()