#!/usr/bin/env python
# 25.py - Bastard v11
# v11:
#  - Tum string literal quoting hatalari duzeltildi (apostrof iceren metinler cift tirnakli)
#  - Versiyon damgasi v11
# v10 ozellikleri korundu:
#  - ETW ready event + user-mode fallback
#  - WMI ready event + registry watchers
#  - ProcMon lib parse hatasi sessizce yutuluyor
#  - Photos No-Action Detector (marker sonrasi 6sn event yoksa uyari)

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, sys, subprocess, queue, winreg, csv
import json, ctypes, atexit, traceback
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
SCRIPT_STEM = Path(__file__).stem or '25'
MAX_EVENT_DETAIL = 500
MAX_UI_PER_TICK = 500
MAX_QUEUE_BEFORE_DROP = 5000


def _find_desktop_early():
    try:
        up = Path(os.environ.get('USERPROFILE', str(Path.home())))
        for c in (up / 'Desktop', up / 'OneDrive' / 'Desktop',
                  up / 'OneDrive' / 'Masaüstü', up / 'Masaüstü'):
            if c.is_dir(): return c
    except Exception: pass
    return Path(os.environ.get('USERPROFILE', str(Path.home())))

_DESKTOP_EARLY = _find_desktop_early()

def _startup_log(msg):
    try:
        p = _DESKTOP_EARLY / f'{SCRIPT_STEM}_startup.log'
        with open(p, 'a', encoding='utf-8') as f:
            f.write(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]} {msg}\n')
    except Exception: pass

def _install_excepthook():
    def _hook(t, v, tb):
        _startup_log('UNCAUGHT: ' + ''.join(traceback.format_exception(t, v, tb)))
        sys.__excepthook__(t, v, tb)
    sys.excepthook = _hook
    try:
        tk.Tk.report_callback_exception = staticmethod(
            lambda *args: _startup_log(f'TK EXC: {args}'))
    except Exception: pass

_startup_log('=' * 60); _startup_log(f'{SCRIPT_STEM} boot')
_install_excepthook()

CONFIG_PATH = (Path(os.environ.get('LOCALAPPDATA', str(Path.home())))
               / 'Bastard' / 'config.json')

def load_config():
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text('utf-8'))
    except Exception: pass
    return {}

def save_config(cfg):
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), 'utf-8')
    except Exception: pass


_shell_execute = ctypes.windll.shell32.ShellExecuteW
_shell_execute.restype = ctypes.c_ssize_t
SW_SHOWNORMAL = 1
SHELL_EXECUTE_ERROR_THRESHOLD = 32

def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError: return False

def _request_elevation():
    exe = sys.executable
    if getattr(sys, 'frozen', False):
        params = ' '.join(f'"{a}"' for a in sys.argv[1:])
    else:
        script = Path(sys.argv[0]).resolve()
        params = ' '.join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
    ret = _shell_execute(None, 'runas', exe, params or None,
                         str(Path.cwd()), SW_SHOWNORMAL)
    if ret <= SHELL_EXECUTE_ERROR_THRESHOLD:
        raise OSError(f'ShellExecuteW failed ({ret})')
    return True

def _show_admin_prompt(parent):
    d = tk.Toplevel(parent); d.title('Administrator'); d.resizable(False, False)
    d.transient(parent); d.grab_set()
    res = {'v': 'continue'}
    f = ttk.Frame(d, padding=20); f.pack(fill='both', expand=True)
    t = ttk.Frame(f); t.pack(fill='x')
    tk.Label(t, text='!', font=('Segoe UI', 36),
             foreground='#f0ad4e').pack(side='left', padx=(0, 16))
    tk.Label(t, justify='left', font=('Segoe UI', 10),
        text=('Administrator privileges recommended.\n\n'
              'ETW kernel sessions require admin.\n\n'
              'Run as administrator now?')).pack(side='left')
    b = ttk.Frame(f); b.pack(fill='x', pady=(20, 0))
    def c(v): res['v'] = v; d.destroy()
    ttk.Button(b, text='Run as Administrator',
               command=lambda: c('elevate')).pack(side='left', padx=4)
    ttk.Button(b, text='Continue Without',
               command=lambda: c('continue')).pack(side='left', padx=4)
    ttk.Button(b, text='Exit',
               command=lambda: c('exit')).pack(side='right', padx=4)
    d.protocol('WM_DELETE_WINDOW', lambda: c('exit'))
    d.update_idletasks()
    w, h = d.winfo_width(), d.winfo_height()
    sw, sh = d.winfo_screenwidth(), d.winfo_screenheight()
    d.geometry(f'+{(sw - w) // 2}+{(sh - h) // 2}')
    parent.wait_window(d)
    return res['v']


def find_desktop():
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("D1", ctypes.c_ulong), ("D2", ctypes.c_ushort),
                        ("D3", ctypes.c_ushort), ("D4", ctypes.c_ubyte * 8)]
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
    except Exception: pass
    return _DESKTOP_EARLY

DESKTOP = find_desktop()

def find_procmon():
    cands = []
    for d in (BASE_DIR, str(DESKTOP), os.getcwd(),
              r'C:\Tools', r'C:\Sysinternals'):
        for n in ('Procmon64.exe', 'Procmon.exe', 'procmon64.exe', 'procmon.exe'):
            cands.append(os.path.join(d, n))
    for p in os.environ.get('PATH', '').split(os.pathsep):
        if not p: continue
        for n in ('Procmon64.exe', 'Procmon.exe'):
            cands.append(os.path.join(p, n))
    for c in cands:
        if os.path.exists(c): return c
    return None

PROCMON_EXE = find_procmon()

SPI_GETDESKWALLPAPER = 0x0073
SPI_SETDESKWALLPAPER = 0x0014
SPIF_UPDATEINIFILE = 0x0001
SPIF_SENDCHANGE    = 0x0002


def _fmt_value(v, max_len=200):
    try: s = str(v)
    except Exception: return '<unprintable>'
    if len(s) > max_len:
        return f'<{len(s)} chars>'
    nonprint = sum(1 for c in s if ord(c) < 9 or (13 < ord(c) < 32) or ord(c) > 126)
    if s and nonprint > len(s) * 0.3:
        return f'<binary {len(s)} bytes>'
    return s


class UEvent:
    __slots__ = ('ts', 'source', 'etype', 'pid', 'details', 'level', 'raw')
    def __init__(self, source, etype, details, pid=None, level='info', raw=None):
        self.ts = datetime.now()
        self.source = source; self.etype = etype; self.pid = pid
        d = str(details) if details is not None else ''
        if len(d) > MAX_EVENT_DETAIL:
            d = d[:MAX_EVENT_DETAIL] + f'... [+{len(d)-MAX_EVENT_DETAIL}]'
        self.details = d
        self.level = level; self.raw = raw
    def to_log_line(self):
        return (f'{self.ts.strftime("%H:%M:%S.%f")[:-3]} '
                f'[{self.source}] [{self.etype}] {self.details}')


def check_shell_verbs(emit):
    emit('--- SHELL VERB CHECK ---', 'info')
    locations = [
        (winreg.HKEY_CLASSES_ROOT, r'SystemFileAssociations\.jpg\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'SystemFileAssociations\.jpeg\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'SystemFileAssociations\.png\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'SystemFileAssociations\image\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'jpegfile\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'pngfile\shell\setaswallpaper'),
        (winreg.HKEY_CLASSES_ROOT, r'Paint.Picture\shell\setaswallpaper'),
        (winreg.HKEY_CURRENT_USER, r'Software\Classes\SystemFileAssociations\.jpg\shell\setaswallpaper'),
    ]
    found = 0
    for hive, path in locations:
        try:
            k = winreg.OpenKey(hive, path)
            try:
                name, _ = winreg.QueryValueEx(k, None)
                emit(f'  [OK] {path} = "{name}"', 'change')
                found += 1
            except FileNotFoundError:
                emit(f'  [OK] {path}', 'change')
                found += 1
            try:
                cmd_k = winreg.OpenKey(k, 'command')
                cmd, _ = winreg.QueryValueEx(cmd_k, None)
                emit(f'       command: {cmd[:200]}', 'change')
                winreg.CloseKey(cmd_k)
            except FileNotFoundError: pass
            winreg.CloseKey(k)
        except FileNotFoundError: pass
        except OSError: pass
    if found == 0:
        emit('  !!! setaswallpaper YOK', 'error')
    else:
        emit(f'  Toplam {found} lokasyonda bulundu', 'info')

    emit('--- IMAGE ASSOCIATION CHECK ---', 'info')
    for ext in ('.jpg', '.jpeg', '.png', '.bmp'):
        try:
            k = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ext)
            try:
                v, _ = winreg.QueryValueEx(k, None)
                emit(f'  {ext} -> ProgID: {v}', 'change')
                try:
                    pk = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f'{v}\\shell')
                    i = 0; verbs = []
                    while True:
                        try:
                            verbs.append(winreg.EnumKey(pk, i)); i += 1
                        except OSError: break
                    winreg.CloseKey(pk)
                    emit(f'       verbs: {", ".join(verbs[:15])}', 'info')
                except FileNotFoundError:
                    emit(f'       {v}\\shell yok!', 'error')
            except FileNotFoundError:
                emit(f'  {ext}: ProgID yok', 'error')
            winreg.CloseKey(k)
        except FileNotFoundError:
            emit(f'  {ext}: kayit yok', 'error')


def check_photos_package(emit):
    emit('--- PHOTOS PACKAGE CHECK ---', 'info')
    try:
        ps = "(Get-AppxPackage Microsoft.Windows.Photos).Capabilities | ForEach-Object { $_.Name }"
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive',
                            '-Command', ps],
                           capture_output=True, text=True, timeout=20,
                           creationflags=NO_WINDOW)
        caps = set()
        for line in (r.stdout or '').splitlines():
            line = line.strip()
            if line: caps.add(line)
        if caps:
            emit(f'  Capabilities: {", ".join(sorted(caps))}', 'change')
            if 'picturesLibrary' not in caps:
                emit('  !!! picturesLibrary YOK', 'error')
        else:
            emit('  Capabilities alinamadi', 'error')
    except Exception as e:
        emit(f'  Hata: {e}', 'error')


def do_photos_reregister(emit):
    emit('--- PHOTOS RE-REGISTER ---', 'info')
    try:
        ps = ("Get-AppxPackage Microsoft.Windows.Photos | "
              "Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "
              "\"$($_.InstallLocation)\\AppXManifest.xml\"}")
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive',
                            '-Command', ps],
                           capture_output=True, text=True, timeout=60,
                           creationflags=NO_WINDOW)
        if r.returncode == 0:
            emit('  Re-register BASARILI', 'change')
        else:
            err = (r.stderr or '')[:400]
            emit(f'  Hata: {err}', 'error')
    except Exception as e:
        emit(f'  Hata: {e}', 'error')


def do_restore_shell_verb(emit):
    emit('--- SHELL VERB RESTORE ---', 'info')
    for ext in ('.jpg', '.png'):
        base = f'Software\\Classes\\SystemFileAssociations\\{ext}\\shell\\setaswallpaper'
        try:
            k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0,
                                   winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(k, None, 0, winreg.REG_SZ, 'Set as desktop background')
            winreg.CloseKey(k)
            cmd_k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                                       base + r'\command', 0,
                                       winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(cmd_k, None, 0, winreg.REG_SZ,
                              r'rundll32.exe "%SystemRoot%\System32\shell32.dll",'
                              r'SetWallpaperFromPicture %1')
            winreg.CloseKey(cmd_k)
            emit(f'  {ext} setaswallpaper geri yuklendi', 'change')
        except Exception as e:
            emit(f'  {ext} Hata: {e}', 'error')


# =================================================================
#  RegistryPoller
# =================================================================
REG_POLL_TARGETS = [
    ('HKCU', r'Control Panel\Desktop'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Lock Screen'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'),
]
HIVE_MAP = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE}


class RegistryPoller(threading.Thread):
    def __init__(self, emit, interval=1.0):
        super().__init__(daemon=True)
        self.emit = emit; self.interval = interval
        self.running = False; self.snapshot = {}

    def _read_all(self):
        out = {}
        for hive_name, base in REG_POLL_TARGETS:
            hive = HIVE_MAP[hive_name]
            for subkey, values in self._read_rec(hive, base, 0).items():
                full = f'{hive_name}\\{subkey}'
                for n, v in values.items():
                    out[f'{full}\\{n}'] = v
        return out

    def _read_rec(self, hive, path, depth):
        result = {}
        if depth > 4: return result
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError: return result
        try:
            vals = {}
            i = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(k, i)
                    vals[n] = _fmt_value(v, 150)
                    i += 1
                except OSError: break
            result[path] = vals
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                    result.update(self._read_rec(hive, path + '\\' + sub, depth + 1))
                    i += 1
                except OSError: break
        finally:
            try: winreg.CloseKey(k)
            except Exception: pass
        return result

    def run(self):
        self.snapshot = self._read_all()
        self.emit(UEvent('RegPoll', 'Process',
            f'Poller aktif ({len(self.snapshot)} deger)', level='info'))
        self.running = True
        while self.running:
            time.sleep(self.interval)
            try: cur = self._read_all()
            except Exception as e:
                self.emit(UEvent('RegPoll', 'Error', f'okuma: {e}', level='error'))
                continue
            self._diff(self.snapshot, cur); self.snapshot = cur

    def _diff(self, old, new):
        for k, v in new.items():
            if k not in old:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[+] {k} = {v}', level='change'))
            elif old[k] != v:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[~] {k}: {old[k]} -> {v}', level='change'))
        for k in old.keys() - new.keys():
            self.emit(UEvent('RegPoll', 'Registry',
                f'[-] {k} silindi', level='change'))

    def stop(self): self.running = False


# =================================================================
#  FileWatch
# =================================================================
def file_watch_targets():
    targets = []
    ad = os.environ.get('APPDATA', ''); la = os.environ.get('LOCALAPPDATA', '')
    if ad: targets.append(os.path.join(ad, 'Microsoft', 'Windows', 'Themes'))
    if la:
        targets.append(os.path.join(la, 'Microsoft', 'Windows', 'Themes'))
        targets.append(os.path.join(la, 'Packages',
                                    'Microsoft.Windows.Photos_8wekyb3d8bbwe'))
    return [t for t in targets if os.path.isdir(t)]


class FileWatchCollector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False; self.observer = None

    def run(self):
        if not HAVE_WATCHDOG:
            self.emit(UEvent('FileWatch', 'Error', 'watchdog yok.', level='error'))
            return
        targets = file_watch_targets()
        if not targets:
            self.emit(UEvent('FileWatch', 'Error', 'hedef yok', level='error'))
            return
        outer = self
        class H(FileSystemEventHandler):
            def on_any_event(self, e):
                if e.is_directory: return
                src = getattr(e, 'src_path', '')
                dst = getattr(e, 'dest_path', '')
                outer.emit(UEvent('FileWatch', 'File',
                    f'{e.event_type}: {src}{(" -> " + dst) if dst else ""}',
                    level='change'))
        self.observer = Observer(); h = H(); ok = 0
        for t in targets:
            try: self.observer.schedule(h, t, recursive=True); ok += 1
            except Exception: pass
        try:
            self.observer.start()
            self.emit(UEvent('FileWatch', 'Process',
                f'Watcher aktif ({ok} klasor)', level='info'))
        except Exception as e:
            self.emit(UEvent('FileWatch', 'Error', f'start: {e}', level='error'))
            return
        self.running = True
        while self.running: time.sleep(0.5)
        try: self.observer.stop(); self.observer.join(timeout=2)
        except Exception: pass

    def stop(self): self.running = False


# =================================================================
#  ProcMon
# =================================================================
PROCMON_PATH_KW = ('wallpaper', 'theme', 'personaliz', 'lockscreen',
                   'transcoded', 'photos', 'runtimebroker', 'immersive',
                   'control panel\\desktop', 'shell')
PROCMON_PROC_HOT = ('photos.exe', 'runtimebroker.exe', 'systemsettings.exe',
                    'shellexperiencehost.exe', 'dllhost.exe', 'explorer.exe',
                    'lockapp.exe', 'backgroundtaskhost.exe',
                    'applicationframehost.exe', 'searchhost.exe',
                    'startmenuexperiencehost.exe')


class ProcMonCollector(threading.Thread):
    def __init__(self, emit, base_dir):
        super().__init__(daemon=True)
        self.emit = emit; self.base_dir = base_dir
        self.running = False; self.proc = None
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pml_path = os.path.join(base_dir, f'{SCRIPT_STEM}_trace_{ts}.pml')
        self.csv_path = os.path.join(base_dir, f'{SCRIPT_STEM}_trace_{ts}.csv')
        self.seen_hashes = set(); self.raw_seen = 0; self.emitted = 0

    def run(self):
        if not PROCMON_EXE:
            self.emit(UEvent('ProcMon', 'Error', 'Procmon64.exe yok.', level='error'))
            return
        self._cleanup_old()
        self._clear_backingfile()
        try:
            cmd = [PROCMON_EXE, '/AcceptEula', '/Quiet', '/Minimized',
                   '/BackingFile', self.pml_path]
            self.proc = subprocess.Popen(
                cmd, creationflags=NO_WINDOW,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=self.base_dir)
            self.emit(UEvent('ProcMon', 'Process',
                f'-> {os.path.basename(self.pml_path)}', level='info'))
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error', f'start: {e}', level='error'))
            return
        time.sleep(2.5)
        if os.path.exists(self.pml_path):
            self.emit(UEvent('ProcMon', 'Process',
                f'PML={os.path.getsize(self.pml_path)}B', level='info'))
        self.running = True
        while self.running:
            for _ in range(8):
                if not self.running: break
                time.sleep(0.25)
            if not self.running: break
        self._shutdown()
        time.sleep(1.5)
        if HAVE_PROCMON_PARSER:
            try: self._parse_with_lib()
            except Exception as e:
                self.emit(UEvent('ProcMon', 'Process',
                    f'lib parse bitti (dosya yarim olabilir): {e}',
                    level='info'))
        if self.raw_seen < 5 and os.path.exists(self.pml_path):
            self.emit(UEvent('ProcMon', 'Process',
                f'lib {self.raw_seen} event, CSV fallback...', level='info'))
            if self._convert_pml_to_csv():
                try: self._parse_csv()
                except Exception as e:
                    self.emit(UEvent('ProcMon', 'Error', f'csv: {e}', level='error'))
        if self.raw_seen < 5:
            self.emit(UEvent('ProcMon', 'Error',
                f'Sadece {self.raw_seen} event.', level='error'))
        else:
            self.emit(UEvent('ProcMon', 'Process',
                f'durdu. {self.raw_seen} raw -> {self.emitted} filt', level='info'))

    def _cleanup_old(self):
        try:
            for f in os.listdir(self.base_dir):
                fl = f.lower()
                if fl.endswith(('.pml', '.csv')) and (
                        fl.startswith(f'{SCRIPT_STEM.lower()}_trace_')
                        or fl.startswith('trace_')
                        or fl.startswith('bastard_trace_')
                        or fl.startswith('a_trace_')
                        or fl.startswith('deepseek_')):
                    try: os.remove(os.path.join(self.base_dir, f))
                    except Exception: pass
        except Exception: pass

    def _clear_backingfile(self):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Sysinternals\Process Monitor', 0,
                winreg.KEY_ALL_ACCESS)
            for v in ('BackingFile', 'LastBackingFile'):
                try: winreg.DeleteValue(k, v)
                except FileNotFoundError: pass
            winreg.CloseKey(k)
        except Exception: pass

    def _shutdown(self):
        if not self.proc: return
        try:
            if self.proc.poll() is None:
                subprocess.run(['taskkill', '/PID', str(self.proc.pid)],
                               capture_output=True, creationflags=NO_WINDOW,
                               timeout=5)
                try: self.proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    subprocess.run(['taskkill', '/F', '/PID', str(self.proc.pid)],
                                   capture_output=True, creationflags=NO_WINDOW,
                                   timeout=5)
        except Exception: pass

    def _parse_with_lib(self):
        if not os.path.exists(self.pml_path): return
        try:
            with open(self.pml_path, 'rb') as f:
                reader = ProcmonLogsReader(f)
                for ev in reader:
                    self._handle(getattr(ev, 'operation', '') or '',
                                 getattr(ev, 'path', '') or '',
                                 getattr(ev, 'result', '') or '',
                                 getattr(ev, 'pid', None),
                                 getattr(ev, 'process_name', '?') or '?',
                                 getattr(ev, 'time_of_day', None))
        except (AttributeError, TypeError):
            pass

    def _convert_pml_to_csv(self):
        try:
            cmd = [PROCMON_EXE, '/AcceptEula', '/Quiet', '/Minimized',
                   '/OpenLog', self.pml_path, '/SaveAs', self.csv_path]
            p = subprocess.Popen(cmd, creationflags=NO_WINDOW,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            try: p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(['taskkill', '/F', '/PID', str(p.pid)],
                               capture_output=True, creationflags=NO_WINDOW,
                               timeout=5)
            time.sleep(1.0)
            if os.path.exists(self.csv_path):
                sz = os.path.getsize(self.csv_path)
                self.emit(UEvent('ProcMon', 'Process', f'CSV: {sz}B', level='info'))
                return sz > 100
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error', f'convert: {e}', level='error'))
        return False

    def _parse_csv(self):
        if not os.path.exists(self.csv_path): return
        try:
            with open(self.csv_path, 'r', encoding='utf-16',
                      errors='replace') as f:
                first = f.readline()
            sep = '\t' if first.count('\t') > first.count(',') else ','
            with open(self.csv_path, 'r', encoding='utf-16',
                      errors='replace') as f:
                reader = csv.DictReader(f, delimiter=sep)
                for row in reader:
                    op = (row.get('Operation') or '')
                    path = (row.get('Path') or '')
                    res = (row.get('Result') or '')
                    pid = (row.get('PID') or '')
                    pname = (row.get('Process Name') or '?')
                    tod = (row.get('Time of Day') or '')
                    try: pid = int(pid) if pid else None
                    except Exception: pid = None
                    self._handle(op, path, res, pid, pname, tod)
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error', f'csv: {e}', level='error'))

    def _handle(self, op, path, res, pid, pname, tod):
        key = (pname, pid, op, str(path), res, str(tod))
        h = hash(key)
        if h in self.seen_hashes: return
        self.seen_hashes.add(h); self.raw_seen += 1
        denied = self._is_denied(res)
        path_low = str(path).lower(); pname_low = str(pname).lower()
        op_upper = str(op).upper()
        is_reg_change = ('REG' in op_upper and any(
            k in op_upper for k in ('SET', 'CREATE', 'DELETE', 'RENAME')))
        is_hot = pname_low in PROCMON_PROC_HOT
        is_hot_path = any(kw in path_low for kw in PROCMON_PATH_KW)
        if not denied and not (is_hot and is_reg_change) and not is_hot_path:
            return
        self.emitted += 1
        etype = self._classify(op)
        if denied:
            self.emit(UEvent('ProcMon', etype,
                f'{op} {path} -> {res} (PID={pid} {pname})',
                pid=pid, level='error'))
        elif etype == 'Registry' and is_reg_change:
            self.emit(UEvent('ProcMon', 'Registry',
                f'{op} {path} -> {res} ({pname})', pid=pid, level='change'))
        elif is_hot_path:
            self.emit(UEvent('ProcMon', etype,
                f'{op} {path} -> {res} ({pname})', pid=pid, level='change'))

    @staticmethod
    def _is_denied(r):
        if not r: return False
        s = str(r).lower()
        return ('access denied' in s or 'erişim engellendi' in s
                or 'privilege not held' in s or 'access is denied' in s)

    @staticmethod
    def _classify(op):
        if not op: return 'Unknown'
        o = str(op).upper()
        if 'REG' in o: return 'Registry'
        if any(k in o for k in ('CREATE', 'WRITE', 'READ', 'SETINFO',
                                'QUERY', 'CLOSE', 'DELETE', 'RENAME', 'FILE')):
            return 'File'
        if 'TCP' in o or 'UDP' in o or 'SEND' in o or 'RECEIVE' in o:
            return 'Network'
        if 'PROCESS' in o or 'THREAD' in o: return 'Process'
        return 'Other'

    def stop(self): self.running = False


# =================================================================
#  ETW  (ready event + user-mode fallback)
# =================================================================
class ETWCollector(threading.Thread):
    KREG = '{70EB4F03-C1DE-4F73-A051-33D13D541355}'
    KFILE = '{EDD08927-9CC4-4E65-B970-C2560FB5C289}'
    SHELL_CORE = '{30336ED4-E327-447C-9DE0-51B2E6059F02}'
    IMMERSIVE = '{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}'
    THEMES     = '{7B67BEC2-6E2F-4A68-B7E4-9D3E9A4C4C8F}'

    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False
        self.sessions = []; self.event_count = 0

    def run(self):
        self.emit(UEvent('ETW', 'Process', 'ETW hazirlaniyor...', level='info'))

        if not HAVE_ETW:
            self.emit(UEvent('ETW', 'Error', 'pywintrace yok.', level='error'))
            return

        kernel_ok = False
        if is_admin():
            kernel_ok = self._try_start('kernel',
                [('Kernel-Registry', self.KREG), ('Kernel-File', self.KFILE)])
        else:
            self.emit(UEvent('ETW', 'Process',
                'Admin degil, kernel ETW atlanip user-mode denenecek',
                level='info'))

        if kernel_ok:
            self.emit(UEvent('ETW', 'Process',
                'ETW KERNEL session aktif', level='info'))
        else:
            self.emit(UEvent('ETW', 'Process',
                "Kernel ETW olmadi, user-mode provider'lar deneniyor...",
                level='info'))
            user_ok = self._try_start('user',
                [('Shell-Core', self.SHELL_CORE),
                 ('Immersive-Shell', self.IMMERSIVE),
                 ('Themes', self.THEMES)])
            if user_ok:
                self.emit(UEvent('ETW', 'Process',
                    'ETW USER-MODE session aktif', level='info'))
            else:
                self.emit(UEvent('ETW', 'Error',
                    'ETW hicbir provider ile baslatilamadi. '
                    'RegPoll + ProcMon + FileWatch devrede.', level='error'))

        self.running = True
        last_report = time.time()
        while self.running:
            time.sleep(0.5)
            now = time.time()
            if now - last_report > 20:
                last_report = now
                if self.event_count == 0:
                    self.emit(UEvent('ETW', 'Process',
                        "ETW hala event almiyor (provider'lar pasif olabilir). "
                        'RegPoll + ProcMon aktif.', level='info'))

        for s in self.sessions:
            try: s.stop()
            except Exception: pass
        self.emit(UEvent('ETW', 'Process',
            f'kapandi. {self.event_count} event.', level='info'))

    def _try_start(self, tag, providers_spec):
        providers = []
        for name, guid in providers_spec:
            try:
                providers.append(etw_mod.ProviderInfo(name, etw_mod.GUID(guid)))
            except Exception as e:
                self.emit(UEvent('ETW', 'Error',
                    f'{tag} ProviderInfo {name}: {e}', level='error'))
        if not providers: return False
        try:
            job = etw_mod.ETW(providers=providers, event_callback=self._on)
            job.start()
            self.sessions.append(job)
            return True
        except Exception as e:
            self.emit(UEvent('ETW', 'Error',
                f'{tag} start hatasi: {e}', level='error'))
            return False

    def _on(self, event):
        try:
            provider = getattr(event, 'provider_name', '?')
            eid = getattr(event, 'event_id', None)
            pid = getattr(event, 'process_id', None)
            payload = getattr(event, 'payload', None)
            parts = []
            if payload and isinstance(payload, dict):
                for k, v in list(payload.items())[:6]:
                    if v is not None and str(v).strip():
                        parts.append(f'{k}={_fmt_value(v, 100)}')
            detail = f'[{provider}] EID={eid} ' + ' | '.join(parts)
            low = detail.lower()
            if ('denied' in low or '0x80070005' in low): level = 'error'
            elif eid in (1, 2, 3, 11, 12, 13): level = 'change'
            else: level = 'info'
            if level == 'info' and not any(kw in low for kw in
                    ('wallpaper', 'theme', 'photos', 'personaliz',
                     'lockscreen', 'transcoded', 'shell')):
                return
            self.event_count += 1
            etype = 'Registry' if 'registry' in str(provider).lower() else 'File'
            self.emit(UEvent('ETW', etype, detail, pid=pid, level=level))
        except Exception: pass

    def stop(self): self.running = False


# =================================================================
#  WMI  (ready event + registry watchers)
# =================================================================
class WMICollector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False; self.watchers = []

    def run(self):
        self.emit(UEvent('WMI', 'Process', 'WMI hazirlaniyor...', level='info'))

        if not HAVE_WMI:
            self.emit(UEvent('WMI', 'Error', 'wmi yok.', level='error'))
            return
        try: pythoncom.CoInitialize()
        except Exception as e:
            self.emit(UEvent('WMI', 'Error', f'CoInit: {e}', level='error'))
            return
        try:
            try: c = wmi.WMI()
            except Exception as e:
                self.emit(UEvent('WMI', 'Error', f'baglan: {e}', level='error'))
                return

            try:
                pw = c.Win32_Process.watch_for('creation')
                self.watchers.append(('process', pw))
                self.emit(UEvent('WMI', 'Process',
                    'Process watcher aktif', level='info'))
            except Exception as e:
                self.emit(UEvent('WMI', 'Error',
                    f'Process watcher: {e}', level='error'))

            reg_keys = [
                ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallPaper'),
                ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallpaperStyle'),
                ('HKEY_CURRENT_USER',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers',
                 'BackgroundType'),
            ]
            reg_ok = 0
            for hive, kp, vn in reg_keys:
                try:
                    w = c.RegistryValueChangeEvent.watch_for(
                        Hive=hive, KeyPath=kp, ValueName=vn)
                    self.watchers.append(('reg', w))
                    reg_ok += 1
                except Exception:
                    pass
            if reg_ok:
                self.emit(UEvent('WMI', 'Process',
                    f'{reg_ok} registry watcher aktif', level='info'))
            else:
                self.emit(UEvent('WMI', 'Process',
                    'WMI registry provider pasif (normal). '
                    'Registry zaten RegPoll ile izleniyor.', level='info'))

            self.running = True
            for k, w in self.watchers:
                threading.Thread(target=self._loop, args=(k, w),
                                 daemon=True).start()
            self.emit(UEvent('WMI', 'Process',
                f'WMI hazir ({len(self.watchers)} watcher)', level='info'))
            while self.running: time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def _loop(self, kind, watcher):
        try: pythoncom.CoInitialize()
        except Exception: pass
        try:
            while self.running:
                try:
                    ev = watcher(timeout_ms=5000)
                    if kind == 'process':
                        pid = getattr(ev, 'ProcessId', None)
                        name = getattr(ev, 'Name', '?')
                        cmd = getattr(ev, 'CommandLine', '') or ''
                        cl = cmd.lower(); nl = name.lower()
                        if nl in ('photos.exe', 'runtimebroker.exe',
                                  'dllhost.exe', 'systemsettings.exe',
                                  'explorer.exe') or any(
                                k in cl for k in ('wallpaper', 'theme',
                                                  'photos', 'lockscreen')):
                            self.emit(UEvent('WMI', 'Process',
                                f'Yeni: {name} PID={pid} {cmd[:200]}',
                                pid=pid, level='info'))
                    else:
                        self.emit(UEvent('WMI', 'Registry',
                            f'{getattr(ev, "KeyPath", "?")} '
                            f'{getattr(ev, "ValueName", "")} = '
                            f'{getattr(ev, "NewValue", "?")}',
                            level='change'))
                except Exception:
                    time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def stop(self): self.running = False


# =================================================================
#  psutil
# =================================================================
class PSUtilCollector(threading.Thread):
    TARGETS = ('photos.exe', 'runtimebroker.exe', 'dllhost.exe',
               'shellexperiencehost.exe', 'explorer.exe', 'sihost.exe',
               'startmenuexperiencehost.exe', 'searchhost.exe',
               'backgroundtaskhost.exe', 'applicationframehost.exe',
               'lockapp.exe', 'systemsettings.exe')
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False; self.seen = set()

    def run(self):
        if not HAVE_PSUTIL:
            self.emit(UEvent('psutil', 'Error', 'psutil yok.', level='error'))
            return
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if (p.info.get('name') or '').lower() in self.TARGETS:
                    self.seen.add(p.pid)
            except Exception: pass
        self.running = True
        last = 0
        while self.running:
            time.sleep(0.5)
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe',
                                              'cmdline', 'ppid']):
                    if p.pid in self.seen: continue
                    self.seen.add(p.pid)
                    try:
                        n = (p.info.get('name') or '').lower()
                        cmd = ' '.join(p.info.get('cmdline') or []) \
                              or (p.info.get('exe') or '')
                        if n in self.TARGETS:
                            self.emit(UEvent('psutil', 'Process',
                                f'YENI: {p.info["name"]} PID={p.pid} '
                                f'{cmd[:200]}', pid=p.pid, level='info'))
                    except Exception: pass
            except Exception: pass
            if time.time() - last > 10:
                last = time.time()
                for p in psutil.process_iter(['pid', 'name', 'status']):
                    try:
                        if (p.info.get('name') or '').lower() == 'photos.exe':
                            self.emit(UEvent('psutil', 'Process',
                                f'Photos PID={p.pid} {p.info.get("status")}',
                                pid=p.pid, level='info'))
                    except Exception: pass

    def stop(self): self.running = False


# =================================================================
#  Win32 / EventLog
# =================================================================
class Win32Collector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False

    def run(self):
        self.running = True
        self.emit(UEvent('Win32', 'Process', 'Win32 hazir', level='info'))
        if HAVE_WIN32:
            self.emit(UEvent('EvtLog', 'Process', 'EventLog hazir', level='info'))
            threading.Thread(target=self._loop, daemon=True).start()
        else:
            self.emit(UEvent('Win32', 'Error', 'pywin32 yok.', level='error'))
        while self.running: time.sleep(0.5)

    def _loop(self):
        cutoff = datetime.now() - timedelta(seconds=60)
        chans = ('Application', 'System')
        last = {}
        backfilled = 0
        for ch in chans:
            h = None
            try:
                h = win32evtlog.OpenEventLog(None, ch)
                flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                         win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                evs = win32evtlog.ReadEventLog(h, flags, 0)
                if evs: last[ch] = evs[0].RecordNumber
                for ev in evs[:200]:
                    try:
                        ts = ev.TimeGenerated
                        try: ts = ts.timetuple()
                        except Exception: pass
                        dt = datetime(*ts[:6]) if isinstance(ts, tuple) \
                             else datetime.now()
                        if dt < cutoff: break
                        if ev.EventType not in (win32con.EVENTLOG_ERROR_TYPE,
                                                win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = 'error' if ev.EventType == \
                              win32con.EVENTLOG_ERROR_TYPE else 'warn'
                        try:
                            msg = ' | '.join(ev.StringInserts) \
                                  if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 350: msg = msg[:350] + '...'
                        low = msg.lower()
                        if any(k in low for k in ('photos', 'wallpaper',
                                'theme', 'runtimebroker', '0x80070005',
                                'access denied', 'immersion', 'shell', 'dwm')):
                            self.emit(UEvent('EvtLog', 'Log',
                                f'[BACKFILL {ch}] {ev.SourceName} '
                                f'ID={ev.EventID & 0xFFFF} {msg}', level=lvl))
                            backfilled += 1
                    except Exception: pass
            except Exception: pass
            finally:
                if h is not None:
                    try: win32evtlog.CloseEventLog(h)
                    except Exception: pass
        self.emit(UEvent('EvtLog', 'Log',
            f'Backfill: {backfilled} kayit' if backfilled else 'Backfill: temiz',
            level='info'))
        self.emit(UEvent('EvtLog', 'Log', 'Canli takip', level='info'))
        while self.running:
            time.sleep(3.0)
            for ch in chans:
                h = None
                try:
                    h = win32evtlog.OpenEventLog(None, ch)
                    flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
                             win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                    l = last.get(ch, 0)
                    evs = win32evtlog.ReadEventLog(h, flags, 0)
                    if not evs: continue
                    mx = l
                    for ev in evs:
                        if ev.RecordNumber <= l: continue
                        mx = max(mx, ev.RecordNumber)
                        if ev.EventType not in (win32con.EVENTLOG_ERROR_TYPE,
                                                win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = 'error' if ev.EventType == \
                              win32con.EVENTLOG_ERROR_TYPE else 'warn'
                        try:
                            msg = ' | '.join(ev.StringInserts) \
                                  if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 400: msg = msg[:400] + '...'
                        self.emit(UEvent('EvtLog', 'Log',
                            f'[{ch}] {ev.SourceName} '
                            f'ID={ev.EventID & 0xFFFF} {msg}', level=lvl))
                    last[ch] = mx
                except Exception: pass
                finally:
                    if h is not None:
                        try: win32evtlog.CloseEventLog(h)
                        except Exception: pass

    def stop(self): self.running = False


# =================================================================
#  UnifiedTracer
# =================================================================
class UnifiedTracer:
    def __init__(self, emit):
        self.emit = emit; self.collectors = []; self.running = False
        self.start_time = None

    def start(self):
        if self.running: return
        self.running = True; self.start_time = datetime.now()
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
        self.emit(UEvent('System', 'Process', f'Desktop: {DESKTOP}', level='info'))
        self.emit(UEvent('System', 'Process', f'BASE_DIR: {BASE_DIR}', level='info'))
        if PROCMON_EXE:
            self.emit(UEvent('System', 'Process',
                f'ProcMon: {PROCMON_EXE}', level='info'))
        if missing:
            self.emit(UEvent('System', 'Error',
                f'Eksik: {", ".join(missing)}', level='error'))

        def _diag(emit):
            def e(m, l='info'): emit(UEvent('Diag', 'Log', m, level=l))
            try:
                check_photos_package(e)
                check_shell_verbs(e)
            except Exception as ex:
                emit(UEvent('Diag', 'Error', f'Diag hata: {ex}', level='error'))
        threading.Thread(target=_diag, args=(self.emit,), daemon=True).start()

        self.emit(UEvent('System', 'Marker',
            ">>> SIMDI: Photos'ta Set As yap.", level='error'))
        collectors = [RegistryPoller(self.emit)]
        if HAVE_WATCHDOG: collectors.append(FileWatchCollector(self.emit))
        if PROCMON_EXE: collectors.append(ProcMonCollector(self.emit, BASE_DIR))
        if HAVE_ETW: collectors.append(ETWCollector(self.emit))
        if HAVE_WMI: collectors.append(WMICollector(self.emit))
        if HAVE_PSUTIL: collectors.append(PSUtilCollector(self.emit))
        if HAVE_WIN32: collectors.append(Win32Collector(self.emit))
        self.collectors = collectors
        for c in collectors: c.start()
        self.emit(UEvent('System', 'Process',
            f'{len(collectors)} collector aktif.', level='info'))

    def stop(self):
        if not self.running: return
        self.running = False
        self.emit(UEvent('System', 'Marker', '>>> DURDURULUYOR...', level='error'))
        for c in self.collectors:
            try: c.stop()
            except Exception: pass
        for c in self.collectors:
            try:
                if c.is_alive(): c.join(timeout=10)
            except Exception: pass
        self.emit(UEvent('System', 'Marker',
            f'=== TRACE BITTI === {datetime.now() - self.start_time}',
            level='error'))


# =================================================================
#  GUI
# =================================================================
class App:
    SOURCES = {
        'Diag':      {'label': 'Diag', 'color': '#00d9ff'},
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
        root.title(f'Bastard v11 ({SCRIPT_STEM})')
        cfg = load_config()
        saved = cfg.get('window_geometry')
        if saved:
            try: root.geometry(saved)
            except Exception: saved = None
        if not saved:
            sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
            w = min(1440, int(sw * 0.9)); h = min(860, int(sh * 0.85))
            root.geometry(f'{w}x{h}+{(sw-w)//2}+{max(20, (sh-h)//2 - 40)}')
        root.minsize(900, 500)

        self.queue = queue.Queue()
        self.tracer = UnifiedTracer(self._emit_u)
        self.log = []
        self.live_log_fh = None; self.live_log_path = None
        self.trace_start_ts = None
        self.current_pml = None
        self._dropped = 0
        self._last_marker_ts = None
        self._marker_action_seen = False

        top = ttk.Frame(root, padding=6); top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='> Trace Baslat', command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='[] Durdur',
                                   command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        self.btn_mark = ttk.Button(top, text='(o) MARKER',
                                   command=self.mark, state='disabled')
        self.btn_mark.pack(side='left', padx=4)
        ttk.Button(top, text='Shell Check',
                   command=self.shell_check).pack(side='left', padx=4)
        ttk.Button(top, text='Shell Restore',
                   command=self.shell_restore).pack(side='left', padx=4)
        ttk.Button(top, text='Photos ReReg',
                   command=self.photos_rereg).pack(side='left', padx=4)
        ttk.Button(top, text='SPI Test',
                   command=self.spi_test).pack(side='left', padx=4)
        ttk.Button(top, text='Bagimlilik',
                   command=self.install_deps).pack(side='left', padx=4)
        ttk.Button(top, text='Log Klasoru',
                   command=self.open_log_folder).pack(side='left', padx=4)
        self.btn_openpml = ttk.Button(top, text='PML Ac',
                                      command=self.open_pml, state='disabled')
        self.btn_openpml.pack(side='left', padx=4)
        ttk.Button(top, text='Reset',
                   command=self.reset_size).pack(side='left', padx=4)
        ttk.Button(top, text='Temizle',
                   command=self.clear).pack(side='left', padx=4)

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
        self.queue_lbl = ttk.Label(stat, text='', foreground='#888',
                                   font=('Consolas', 9))
        self.queue_lbl.pack(side='right', padx=8)
        self.log_path_lbl = ttk.Label(stat, text='', foreground='#666')
        self.log_path_lbl.pack(side='right')

        guide = ttk.LabelFrame(root, text='SORUN TESPIT AKISI', padding=4)
        guide.pack(fill='x', padx=6, pady=(4, 0))
        ttk.Label(guide,
            text='1) Trace Baslat -> Diag otomatik  '
                 '2) SPI Test ile API dogrula  '
                 '3) Shell Check/Restore  '
                 "4) Photos'ta Set As -> MARKER  "
                 '5) 20 sn bekle -> Durdur',
            foreground='#c8d6e5').pack(anchor='w')

        filt = ttk.LabelFrame(root, text='Filtre', padding=6)
        filt.pack(fill='x', padx=6, pady=(4, 0))
        self.f_sources = {}
        for src, meta in self.SOURCES.items():
            var = tk.BooleanVar(value=True)
            self.f_sources[src] = var
            ttk.Checkbutton(filt, text=meta['label'], variable=var,
                            command=self.refilter).pack(side='left', padx=2)
        ttk.Separator(filt, orient='vertical').pack(side='left', fill='y', padx=8)
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
        root.after(80, self._drain)
        root.after(500, self._tick)

    def shell_check(self):
        def _run():
            def e(m, l='info'): self._emit_u(UEvent('Diag', 'Log', m, level=l))
            try: check_shell_verbs(e)
            except Exception as ex:
                e(f'Shell check hata: {ex}', 'error')
        threading.Thread(target=_run, daemon=True).start()

    def shell_restore(self):
        if not messagebox.askyesno('Shell Restore',
                "HKCU altina .jpg ve .png icin setaswallpaper verb'unu "
                "geri yukle?"):
            return
        def _run():
            def e(m, l='info'): self._emit_u(UEvent('Diag', 'Log', m, level=l))
            try:
                do_restore_shell_verb(e)
                e('Restore sonrasi Shell Check...', 'info')
                check_shell_verbs(e)
            except Exception as ex:
                e(f'Restore hata: {ex}', 'error')
        threading.Thread(target=_run, daemon=True).start()

    def photos_rereg(self):
        def _run():
            def e(m, l='info'): self._emit_u(UEvent('Diag', 'Log', m, level=l))
            try: do_photos_reregister(e)
            except Exception as ex:
                e(f'ReReg hata: {ex}', 'error')
        threading.Thread(target=_run, daemon=True).start()

    def spi_test(self):
        p = filedialog.askopenfilename(
            title='Wallpaper yapilacak resmi sec',
            initialdir=str(DESKTOP),
            filetypes=[('Resim', '*.jpg *.jpeg *.png *.bmp *.gif'),
                       ('Tumu', '*.*')])
        if not p: return
        self._emit_u(UEvent('System', 'Process', f'SPI Test: {p}', level='info'))
        def _run():
            try:
                ok = ctypes.windll.user32.SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER, 0, p,
                    SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
                if ok:
                    self._emit_u(UEvent('System', 'Process',
                        f'SPI Test BASARILI -> {p}', level='info'))
                else:
                    err = ctypes.get_last_error()
                    self._emit_u(UEvent('System', 'Error',
                        f'SPI Test FAIL err={err}', level='error'))
            except Exception as e:
                self._emit_u(UEvent('System', 'Error', f'SPI: {e}',
                                    level='error'))
        threading.Thread(target=_run, daemon=True).start()

    def open_pml(self):
        if not self.current_pml or not os.path.exists(self.current_pml):
            messagebox.showwarning('PML', 'PML yok.'); return
        if not PROCMON_EXE:
            messagebox.showwarning('PML', 'Procmon64.exe yok.'); return
        try:
            subprocess.Popen([PROCMON_EXE, '/OpenLog', self.current_pml],
                             creationflags=NO_WINDOW)
        except Exception as e:
            messagebox.showerror('PML', f'{e}')

    def reset_size(self):
        sw = self.root.winfo_screenwidth(); sh = self.root.winfo_screenheight()
        w = min(1440, int(sw * 0.9)); h = min(860, int(sh * 0.85))
        self.root.geometry(f'{w}x{h}+{(sw-w)//2}+{max(20, (sh-h)//2 - 40)}')

    def _save_geometry(self):
        try:
            cfg = load_config()
            cfg['window_geometry'] = (
                f'{self.root.winfo_width()}x{self.root.winfo_height()}'
                f'+{self.root.winfo_x()}+{self.root.winfo_y()}')
            save_config(cfg)
        except Exception: pass

    def _tick(self):
        if self.trace_start_ts:
            e = datetime.now() - self.trace_start_ts
            self.timer_lbl.config(text=f'[T] {int(e.total_seconds())} sn')
        qs = self.queue.qsize()
        if qs > 200:
            self.queue_lbl.config(text=f'queue={qs} drop={self._dropped}',
                                  foreground='#ff6b6b' if qs > 2000
                                  else '#f0c060')
        else:
            self.queue_lbl.config(text='')

        # Marker sonrasi action gorulmediyse 6 sn sonra uyar
        if self._last_marker_ts and not self._marker_action_seen:
            if datetime.now() - self._last_marker_ts > timedelta(seconds=6):
                self._emit_u(UEvent('System', 'Marker',
                    "!!! MARKER sonrasi 6sn gecti, hicbir wallpaper "
                    "event'i yok. Photos 'Set as' bos dondu. "
                    "Cozum: Explorer sag-tik -> 'Set as desktop background'",
                    level='error'))
                self._marker_action_seen = True
        self.root.after(500, self._tick)

    def _open_logfile(self):
        self._close_logfile()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.live_log_path = DESKTOP / f'{SCRIPT_STEM}_{ts}.log'
        try:
            self.live_log_fh = open(self.live_log_path, 'w', encoding='utf-8')
            self.live_log_fh.write(
                f'# Bastard v11 ({SCRIPT_STEM}) - {datetime.now()}\n'
                f'# Admin: {is_admin()}\n# Desktop: {DESKTOP}\n'
                f'# BASE_DIR: {BASE_DIR}\n')
            self.live_log_fh.flush()
            self.log_path_lbl.config(text=f'Log: {self.live_log_path.name}')
        except Exception as e:
            messagebox.showerror('Log', f'{e}'); self.live_log_fh = None

    def _close_logfile(self):
        if self.live_log_fh:
            try:
                self.live_log_fh.write(f'# KAPANDI: {datetime.now()}\n')
                self.live_log_fh.flush(); self.live_log_fh.close()
            except Exception: pass
            self.live_log_fh = None

    def _write_live(self, ev):
        if not self.live_log_fh: return
        try:
            self.live_log_fh.write(ev.to_log_line() + '\n')
            self.live_log_fh.flush()
        except Exception: pass

    def _emit_u(self, ev): self.queue.put(ev)

    def _drain(self):
        processed = 0
        try:
            while processed < MAX_UI_PER_TICK:
                ev = self.queue.get_nowait()
                self.log.append(ev)
                self._write_live(ev)
                if self._passes(ev): self._write_event(ev)
                if ev.source in self.collector_labels:
                    self.collector_labels[ev.source].config(fg='green')
                if self._last_marker_ts and not self._marker_action_seen:
                    if (ev.source in ('RegPoll', 'FileWatch', 'ProcMon',
                                      'ETW', 'WMI')
                            and ev.etype in ('Registry', 'File')):
                        if any(k in ev.details.lower() for k in
                               ('wallpaper', 'wallpaperstyle', 'transcoded',
                                'backgroundhistory', 'cachedimage')):
                            self._marker_action_seen = True
                            self._emit_u(UEvent('System', 'Marker',
                                ">>> Photos 'Set as' calisti "
                                "(wallpaper event yakalandi) <<<",
                                level='error'))
                if (ev.source == 'ProcMon' and '->' in ev.details
                        and not self.current_pml):
                    try:
                        for f in os.listdir(BASE_DIR):
                            if (f.startswith(SCRIPT_STEM)
                                    and f.endswith('.pml')):
                                self.current_pml = os.path.join(BASE_DIR, f)
                                self.btn_openpml.config(state='normal')
                                break
                    except Exception: pass
                processed += 1
        except queue.Empty:
            pass
        if self.queue.qsize() > MAX_QUEUE_BEFORE_DROP:
            drop = 0
            while self.queue.qsize() > 2000:
                try:
                    self.queue.get_nowait(); drop += 1
                except queue.Empty: break
            if drop:
                self._dropped += drop
                self._write_event(UEvent('System', 'Error',
                    f'UI geri kaldi, {drop} event atlandi', level='error'))
        self.root.after(80, self._drain)

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
        src = f'[{ev.source}]'; et = f'[{ev.etype}]'
        if ev.etype == 'Marker': tag = 'marker'
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
        self._last_marker_ts = None
        self._marker_action_seen = False
        threading.Thread(target=self.tracer.start, daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_mark.config(state='normal')

    def mark(self):
        self._last_marker_ts = datetime.now()
        self._marker_action_seen = False
        self._emit_u(UEvent('System', 'Marker',
            '>>> MARKER: Set As bu anda denendi <<<', level='error'))

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.btn_mark.config(state='disabled')
        self.root.after(12000, self._close_logfile)
        self.trace_start_ts = None
        self._last_marker_ts = None

    def _on_close(self):
        self._save_geometry()
        try: self.tracer.stop()
        except Exception: pass
        time.sleep(0.5); self._close_logfile()
        self.root.destroy()

    def install_deps(self):
        if not messagebox.askyesno('Bagimlilik',
                'psutil, wmi, pywin32, pywintrace, procmon-parser, watchdog?'):
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
            except Exception as ex:
                self._emit_u(UEvent('System', 'Error',
                    f'pip: {ex}', level='error'))
        threading.Thread(target=_run, daemon=True).start()

    def open_log_folder(self):
        try: os.startfile(str(DESKTOP))
        except Exception as ex: messagebox.showerror('Hata', str(ex))

    def clear(self):
        self.log.clear(); self.txt.delete('1.0', 'end')


def main():
    _startup_log('main entry')
    root = tk.Tk(); root.withdraw()
    try: root.call('tk', 'scaling', 1.1)
    except Exception: pass
    if not is_admin():
        choice = _show_admin_prompt(root)
        if choice == 'elevate':
            try:
                _request_elevation(); root.destroy(); return 0
            except OSError as exc:
                messagebox.showerror('Elevation Failed', f'{exc}')
        elif choice == 'exit':
            root.destroy(); return 0
    App(root)
    root.update_idletasks()
    root.deiconify()
    root.mainloop()
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as e:
        _startup_log(f'FATAL: {e}\n{traceback.format_exc()}')
        raise