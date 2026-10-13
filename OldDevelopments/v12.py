
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
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
SCRIPT_STEM = Path(__file__).stem or '21'


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


def _test_reg_write(hive, path, name, emit):
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
    except PermissionError as e:
        emit(f'  [ACL] {path}\\{name}: OPEN REDDEDILDI -> {e}'); return False
    except FileNotFoundError:
        emit(f'  [ACL] {path}\\{name}: key yok'); return None
    except OSError as e:
        emit(f'  [ACL] {path}\\{name}: open hata -> {e}'); return False
    try:
        try: cur, cur_type = winreg.QueryValueEx(k, name)
        except FileNotFoundError: cur, cur_type = '', winreg.REG_SZ
        winreg.SetValueEx(k, name, 0, cur_type, cur)
        emit(f'  [ACL] {path}\\{name}: YAZILABILIR'); return True
    except PermissionError as e:
        emit(f'  [ACL] {path}\\{name}: YAZMA REDDEDILDI -> {e}'); return False
    except OSError as e:
        emit(f'  [ACL] {path}\\{name}: yazma hata -> {e}'); return False
    finally:
        try: winreg.CloseKey(k)
        except Exception: pass

def _test_spi_get(emit):
    try:
        u = ctypes.windll.user32
        buf = ctypes.create_unicode_buffer(512)
        ok = u.SystemParametersInfoW(SPI_GETDESKWALLPAPER, 512, buf, 0)
        if ok:
            emit(f'  [API] SPI_GET OK -> "{buf.value}"'); return buf.value
        emit(f'  [API] SPI_GET FAIL (err={ctypes.get_last_error()})')
        return None
    except Exception as e:
        emit(f'  [API] SPI_GET EXC -> {e}'); return None

def _test_spi_set(emit, path):
    if not path:
        emit('  [API] SPI_SET atlandi (yol yok)'); return None
    try:
        ok = ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 0, path,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
        if ok:
            emit('  [API] SPI_SET OK'); return True
        emit(f'  [API] SPI_SET FAIL (err={ctypes.get_last_error()})'); return False
    except Exception as e:
        emit(f'  [API] SPI_SET EXC -> {e}'); return None

def _test_transcoded(emit):
    ad = os.environ.get('APPDATA', '')
    p = os.path.join(ad, 'Microsoft', 'Windows', 'Themes', 'TranscodedWallpaper')
    if not os.path.exists(p):
        emit(f'  [FILE] Yok: {p}'); return None
    try:
        with open(p, 'ab'): pass
        emit('  [FILE] TranscodedWallpaper YAZILABILIR'); return True
    except Exception as e:
        emit(f'  [FILE] YAZMA REDDEDILDI -> {e}'); return False

def _test_icacls(emit, hive_str, path):
    try:
        target = f'{hive_str}\\{path}'
        r = subprocess.run(['icacls', target], capture_output=True,
                           text=True, timeout=8, creationflags=NO_WINDOW)
        out = (r.stdout or '').strip()
        if not out:
            emit(f'  [ACL-DUMP] {target}: cikti yok'); return
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            if line.lower().startswith(target.lower()):
                emit(f'  [ACL-DUMP] {line}')
            elif any(x in line for x in (':(F)', ':(R)', ':(W)', ':(M)')):
                emit(f'    {line}')
        if 'DENY' in out.upper():
            emit('  [ACL-DUMP] !!! DENY kurali var')
    except Exception as e:
        emit(f'  [ACL-DUMP] hata: {e}')


def _run_ps(cmd, timeout=25):
    try:
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW)
        return (r.stdout or '').strip()
    except Exception as e:
        return f'PS ERROR: {e}'


class DeepPrecheck(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit

    def run(self):
        def say(m, lvl='info'):
            self.emit(UEvent('Precheck', 'Log', m, level=lvl))
        def warn(m):
            self.emit(UEvent('Precheck', 'Error', m, level='error'))

        say('===== DEEP PRECHECK v7 =====')
        say(f'Admin: {"EVET" if is_admin() else "HAYIR"}')

        say('[Registry Testleri]')
        for hive, path, name in (
            (winreg.HKEY_CURRENT_USER, r'Control Panel\Desktop', 'WallPaper'),
            (winreg.HKEY_CURRENT_USER, r'Control Panel\Desktop', 'WallpaperStyle'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers', 'BackgroundType'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Themes', 'CurrentTheme'),
        ):
            _test_reg_write(hive, path, name, lambda m: say(m, 'change'))

        say('[Wallpaper API]')
        cur = _test_spi_get(lambda m: say(m, 'change'))
        _test_spi_set(lambda m: say(m, 'change'), cur)

        say('[Dosya]')
        _test_transcoded(lambda m: say(m, 'change'))

        say('[Policy Deep Scan]')
        policies = [
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 'WallpaperStyle'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoSaveSettings'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingLockScreen'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'WallpaperStyle'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoChangingLockScreen'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoLockScreen'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\System', 'DisableLogonBackgroundImage'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'LockScreenImagePath'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'LockScreenImageUrl'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'DesktopImagePath'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'DesktopImageUrl'),
        ]
        found = False
        for hive_str, path, name in policies:
            hive = winreg.HKEY_CURRENT_USER if hive_str == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
            try:
                k = winreg.OpenKey(hive, path)
                try:
                    v, _ = winreg.QueryValueEx(k, name)
                    lvl = 'error' if (isinstance(v, int) and v != 0) else 'info'
                    msg = f'  >> {hive_str}\\{path}\\{name} = {v}'
                    if lvl == 'error':
                        warn(msg + '  <<< AKTIF ENGELLEME')
                    else:
                        say(msg + '  (0 = pasif)')
                    found = True
                except FileNotFoundError: pass
                winreg.CloseKey(k)
            except (FileNotFoundError, OSError): pass
        if not found: say('  Politika yok (iyi)')

        say('[ACL Dump]')
        _test_icacls(lambda m: say(m, 'change'), 'HKCU', r'Control Panel\Desktop')

        say('[Servisler]')
        if HAVE_PSUTIL:
            for svc in ('Themes', 'AppXSvc', 'ClipSVC', 'StateRepository',
                        'TokenBroker', 'ShellHWDetection'):
                try:
                    s = psutil.win_service_get(svc); d = s.as_dict()
                    if d.get('status') != 'running' or d.get('start_type') == 'disabled':
                        warn(f'  >> SORUNLU: {svc} {d.get("status")}/{d.get("start_type")}')
                    else: say(f'  OK: {svc}')
                except Exception:
                    pass

        say('[Photos AppX]')
        out = _run_ps("Get-AppxPackage Microsoft.Windows.Photos | "
                      "Select-Object Name,Version,Status,InstallLocation | "
                      "Format-List | Out-String")
        for line in out.splitlines()[:8]:
            if line.strip(): say(f'  {line.strip()}')

        say('[Photos Capabilities]')
        out = _run_ps("(Get-AppxPackage Microsoft.Windows.Photos).Capabilities | "
                      "ForEach-Object { $_.Name }")
        if out:
            for line in out.splitlines()[:30]:
                if line.strip(): say(f'  CAP: {line.strip()}')
        else:
            warn('  Capabilities bilgisi alinamadi')

        say('[AppxManifest Rescap]')
        out = _run_ps(
            "$loc = (Get-AppxPackage Microsoft.Windows.Photos).InstallLocation; "
            "if ($loc) { "
            "  [xml]$m = Get-Content (Join-Path $loc 'AppxManifest.xml'); "
            "  $m.Package.Capabilities.ChildNodes | "
            "  ForEach-Object { $_.Name } | Select-Object -Unique "
            "}")
        if out:
            for line in out.splitlines()[:40]:
                if line.strip(): say(f'  RESCAP: {line.strip()}')

        say('[Windows Apps - Set As Handler]')
        out = _run_ps(
            "Get-ChildItem 'HKLM:\\SOFTWARE\\Classes\\*\\shell\\*' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.PSChildName -match 'Set|Wallpaper|Background' } | "
            "Select-Object -First 20 -ExpandProperty PSChildName")
        if out:
            for line in out.splitlines()[:20]:
                if line.strip(): say(f'  SHELL: {line.strip()}')

        say('===== PRECHECK BITTI =====')


class UEvent:
    __slots__ = ('ts', 'source', 'etype', 'pid', 'details', 'level', 'raw')
    def __init__(self, source, etype, details, pid=None, level='info', raw=None):
        self.ts = datetime.now(); self.source = source; self.etype = etype
        self.pid = pid; self.details = details; self.level = level; self.raw = raw
    def to_log_line(self):
        return (f'{self.ts.strftime("%H:%M:%S.%f")[:-3]} '
                f'[{self.source}] [{self.etype}] {self.details}')


REG_POLL_TARGETS = [
    ('HKCU', r'Control Panel\Desktop'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Lock Screen'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'),
]
HIVE_MAP = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE}

def file_watch_targets():
    targets = []
    ad = os.environ.get('APPDATA', ''); la = os.environ.get('LOCALAPPDATA', '')
    if ad: targets.append(os.path.join(ad, 'Microsoft', 'Windows', 'Themes'))
    if la:
        targets.append(os.path.join(la, 'Microsoft', 'Windows', 'Themes'))
        targets.append(os.path.join(la, 'Packages',
                                    'Microsoft.Windows.Photos_8wekyb3d8bbwe'))
    return [t for t in targets if os.path.isdir(t)]

PROCMON_PATH_KW = ('wallpaper', 'theme', 'personaliz', 'lockscreen',
                   'transcoded', 'photos', 'runtimebroker', 'immersive',
                   'control panel\\desktop', 'shell')
PROCMON_PROC_HOT = ('photos.exe', 'runtimebroker.exe', 'systemsettings.exe',
                    'shellexperiencehost.exe', 'dllhost.exe', 'explorer.exe',
                    'lockapp.exe', 'backgroundtaskhost.exe',
                    'applicationframehost.exe', 'searchhost.exe',
                    'startmenuexperiencehost.exe')


class RegistryPoller(threading.Thread):
    def __init__(self, emit, interval=0.5):
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
                    try: vals[n] = str(v)
                    except Exception: vals[n] = repr(v)
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
        for k, v in old.items():
            if k not in new:
                self.emit(UEvent('RegPoll', 'Registry',
                    f'[-] {k} silindi', level='change'))

    def stop(self): self.running = False


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
                self.emit(UEvent('ProcMon', 'Error',
                    f'lib parse: {e}', level='error'))

        if self.raw_seen < 5 and os.path.exists(self.pml_path):
            self.emit(UEvent('ProcMon', 'Process',
                f'lib sadece {self.raw_seen} event verdi. '
                f'ProcMon ile CSV cevirisi deneniyor...', level='info'))
            if self._convert_pml_to_csv():
                try: self._parse_csv()
                except Exception as e:
                    self.emit(UEvent('ProcMon', 'Error',
                        f'csv parse: {e}', level='error'))

        if self.raw_seen < 5:
            sz = os.path.getsize(self.pml_path) if os.path.exists(self.pml_path) else 0
            self.emit(UEvent('ProcMon', 'Error',
                f'ProcMon hala {self.raw_seen} event. '
                f'PML={sz}B, CSV={os.path.basename(self.csv_path) if os.path.exists(self.csv_path) else "yok"}. '
                f'PML manuel acilabilir: {self.pml_path}', level='error'))
        else:
            self.emit(UEvent('ProcMon', 'Process',
                f'durdu. {self.raw_seen} raw -> {self.emitted} filt', level='info'))

    def _cleanup_old(self):
        try:
            for f in os.listdir(self.base_dir):
                fl = f.lower()
                if (fl.startswith(f'{SCRIPT_STEM.lower()}_trace_')
                        or fl.startswith('trace_')
                        or fl.startswith('bastard_trace_')
                        or fl.startswith('a_trace_')):
                    if fl.endswith(('.pml', '.csv')):
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
                               capture_output=True, creationflags=NO_WINDOW, timeout=5)
                try: self.proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    subprocess.run(['taskkill', '/F', '/PID', str(self.proc.pid)],
                                   capture_output=True, creationflags=NO_WINDOW, timeout=5)
        except Exception: pass

    def _parse_with_lib(self):
        if not os.path.exists(self.pml_path): return
        with open(self.pml_path, 'rb') as f:
            reader = ProcmonLogsReader(f)
            for ev in reader:
                self._handle_event(
                    getattr(ev, 'operation', '') or '',
                    getattr(ev, 'path', '') or '',
                    getattr(ev, 'result', '') or '',
                    getattr(ev, 'pid', None),
                    getattr(ev, 'process_name', '?') or '?',
                    getattr(ev, 'time_of_day', None))

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
                               capture_output=True, creationflags=NO_WINDOW, timeout=5)
            time.sleep(1.0)
            if os.path.exists(self.csv_path):
                sz = os.path.getsize(self.csv_path)
                self.emit(UEvent('ProcMon', 'Process',
                    f'CSV olustu: {sz}B', level='info'))
                return sz > 100
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error', f'convert: {e}', level='error'))
        return False

    def _parse_csv(self):
        if not os.path.exists(self.csv_path): return
        try:
            for enc in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
                try:
                    with open(self.csv_path, 'r', encoding=enc,
                              errors='replace') as f:
                        first = f.readline()
                        break
                except Exception:
                    continue
            else:
                return
            sep = '\t' if first.count('\t') > first.count(',') else ','
            with open(self.csv_path, 'r', encoding=enc, errors='replace') as f:
                reader = csv.DictReader(f, delimiter=sep)
                for row in reader:
                    op = (row.get('Operation') or row.get('operation') or '')
                    path = (row.get('Path') or row.get('path') or '')
                    res = (row.get('Result') or row.get('result') or '')
                    pid = (row.get('PID') or row.get('pid') or None)
                    pname = (row.get('Process Name') or
                             row.get('process_name') or '?')
                    tod = (row.get('Time of Day') or '')
                    try: pid = int(pid) if pid else None
                    except Exception: pid = None
                    self._handle_event(op, path, res, pid, pname, tod)
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error', f'csv: {e}', level='error'))

    def _handle_event(self, op, path, res, pid, pname, tod):
        key = (pname, pid, op, str(path), res, str(tod))
        h = hash(key)
        if h in self.seen_hashes: return
        self.seen_hashes.add(h); self.raw_seen += 1
        denied = self._is_denied(res)
        path_low = str(path).lower(); pname_low = str(pname).lower()
        op_upper = str(op).upper()
        is_reg_change = ('REG' in op_upper and any(
            k in op_upper for k in ('SET', 'CREATE', 'DELETE', 'RENAME')))
        is_hot_proc = pname_low in PROCMON_PROC_HOT
        is_hot_path = any(kw in path_low for kw in PROCMON_PATH_KW)
        if not denied and not (is_hot_proc and is_reg_change) and not is_hot_path:
            return
        self.emitted += 1
        etype = self._classify(op)
        if denied:
            self.emit(UEvent('ProcMon', etype,
                f'{op} {path} -> {res} (PID={pid} {pname})', pid=pid, level='error'))
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


class ETWCollector(threading.Thread):
    KREG = '{70EB4F03-C1DE-4F73-A051-33D13D541355}'
    KFILE = '{EDD08927-9CC4-4E65-B970-C2560FB5C289}'
    SHELL = '{30336ED4-E327-447C-9DE0-51B2E6059F02}'
    IMM = '{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}'

    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False
        self.sessions = []; self.event_count = 0

    def run(self):
        if not HAVE_ETW:
            self.emit(UEvent('ETW', 'Error', 'pywintrace yok.', level='error')); return
        if not is_admin():
            self.emit(UEvent('ETW', 'Error', 'admin gerekli', level='error')); return
        providers = []
        for name, guid in (('Kernel-Registry', self.KREG),
                           ('Kernel-File', self.KFILE),
                           ('Shell-Core', self.SHELL),
                           ('Immersive-Shell', self.IMM)):
            try:
                providers.append(etw_mod.ProviderInfo(name, etw_mod.GUID(guid)))
            except Exception: pass
        if not providers: return
        self.emit(UEvent('ETW', 'Process',
            f'{len(providers)} provider', level='info'))
        try:
            job = etw_mod.ETW(providers=providers, event_callback=self._on)
            job.start(); self.sessions.append(job)
            self.emit(UEvent('ETW', 'Process', 'session basladi', level='info'))
        except Exception as e:
            self.emit(UEvent('ETW', 'Error', f'start: {e}', level='error')); return
        self.running = True
        last = time.time()
        while self.running:
            time.sleep(0.5)
            if time.time() - last > 15:
                last = time.time()
                if self.event_count == 0:
                    self.emit(UEvent('ETW', 'Process',
                        '15 sn event yok', level='info'))
        for s in self.sessions:
            try: s.stop()
            except Exception: pass
        self.emit(UEvent('ETW', 'Process',
            f'kapandi. {self.event_count} event', level='info'))

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
                        parts.append(f'{k}={v}')
            detail = f'[{provider}] EID={eid} ' + ' | '.join(parts)
            low = detail.lower()
            if ('denied' in low or '0x80070005' in low): level = 'error'
            elif eid in (1, 2, 3, 11, 12, 13): level = 'change'
            else: level = 'info'
            if level == 'info' and not any(kw in low for kw in
                    ('wallpaper', 'theme', 'photos', 'personaliz',
                     'lockscreen', 'transcoded')):
                return
            self.event_count += 1
            etype = 'Registry' if 'registry' in str(provider).lower() else 'File'
            self.emit(UEvent('ETW', etype, detail, pid=pid, level=level))
        except Exception: pass

    def stop(self): self.running = False


class WMICollector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit; self.running = False; self.watchers = []

    def run(self):
        if not HAVE_WMI:
            self.emit(UEvent('WMI', 'Error', 'wmi yok.', level='error')); return
        try: pythoncom.CoInitialize()
        except Exception: return
        try:
            try: c = wmi.WMI()
            except Exception as e:
                self.emit(UEvent('WMI', 'Error', f'baglan: {e}', level='error')); return
            try:
                pw = c.Win32_Process.watch_for('creation')
                self.watchers.append(('process', pw))
                self.emit(UEvent('WMI', 'Process', 'watcher aktif', level='info'))
            except Exception as e:
                self.emit(UEvent('WMI', 'Error', f'watcher: {e}', level='error'))
            self.running = True
            for k, w in self.watchers:
                threading.Thread(target=self._loop, args=(k, w), daemon=True).start()
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
                    ev = watcher(timeout_ms=3000)
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
                except Exception:
                    time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def stop(self): self.running = False


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
            self.emit(UEvent('psutil', 'Error', 'psutil yok.', level='error')); return
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if (p.info.get('name') or '').lower() in self.TARGETS:
                    self.seen.add(p.pid)
            except Exception: pass
        self.running = True
        last = 0
        while self.running:
            time.sleep(0.35)
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
                    if p.pid in self.seen: continue
                    self.seen.add(p.pid)
                    try:
                        n = (p.info.get('name') or '').lower()
                        cmd = ' '.join(p.info.get('cmdline') or []) \
                              or (p.info.get('exe') or '')
                        if n in self.TARGETS:
                            self.emit(UEvent('psutil', 'Process',
                                f'YENI: {p.info["name"]} PID={p.pid} {cmd[:200]}',
                                pid=p.pid, level='info'))
                    except Exception: pass
            except Exception: pass
            if time.time() - last > 8:
                last = time.time()
                for p in psutil.process_iter(['pid', 'name', 'status']):
                    try:
                        if (p.info.get('name') or '').lower() == 'photos.exe':
                            self.emit(UEvent('psutil', 'Process',
                                f'Photos PID={p.pid} {p.info.get("status")}',
                                pid=p.pid, level='info'))
                    except Exception: pass

    def stop(self): self.running = False


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
                        dt = datetime(*ts[:6]) if isinstance(ts, tuple) else datetime.now()
                        if dt < cutoff: break
                        if ev.EventType not in (win32con.EVENTLOG_ERROR_TYPE,
                                                win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = 'error' if ev.EventType == win32con.EVENTLOG_ERROR_TYPE else 'warn'
                        try: msg = ' | '.join(ev.StringInserts) if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 350: msg = msg[:350] + '...'
                        low = msg.lower()
                        if any(k in low for k in ('photos', 'wallpaper', 'theme',
                                'runtimebroker', '0x80070005', 'access denied',
                                'immersion', 'shell', 'dwm')):
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
            time.sleep(2.0)
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
                        lvl = 'error' if ev.EventType == win32con.EVENTLOG_ERROR_TYPE else 'warn'
                        try: msg = ' | '.join(ev.StringInserts) if ev.StringInserts else ''
                        except Exception: msg = ''
                        if len(msg) > 400: msg = msg[:400] + '...'
                        self.emit(UEvent('EvtLog', 'Log',
                            f'[{ch}] {ev.SourceName} ID={ev.EventID & 0xFFFF} {msg}',
                            level=lvl))
                    last[ch] = mx
                except Exception: pass
                finally:
                    if h is not None:
                        try: win32evtlog.CloseEventLog(h)
                        except Exception: pass

    def stop(self): self.running = False


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
            self.emit(UEvent('System', 'Process', f'ProcMon: {PROCMON_EXE}', level='info'))
        if missing:
            self.emit(UEvent('System', 'Error', f'Eksik: {", ".join(missing)}', level='error'))
        DeepPrecheck(self.emit).start()
        self.emit(UEvent('System', 'Marker',
            '>>> SIMDI: Photos\'ta Set As yap.', level='error'))
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
            f'=== TRACE BITTI === {datetime.now() - self.start_time}', level='error'))


class App:
    SOURCES = {
        'Precheck':  {'label': 'Precheck', 'color': '#ff00ff'},
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
        root.title(f'Bastard v7 ({SCRIPT_STEM})')
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

        top = ttk.Frame(root, padding=6); top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='> Trace Baslat', command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='[] Durdur',
                                   command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        self.btn_mark = ttk.Button(top, text='(o) MARKER',
                                   command=self.mark, state='disabled')
        self.btn_mark.pack(side='left', padx=4)
        ttk.Button(top, text='Precheck',
                   command=self.precheck).pack(side='left', padx=4)
        self.btn_spitest = ttk.Button(top, text='SPI Test',
                                      command=self.spi_test)
        self.btn_spitest.pack(side='left', padx=4)
        ttk.Button(top, text='Bagimlilik',
                   command=self.install_deps).pack(side='left', padx=4)
        ttk.Button(top, text='Log Klasoru',
                   command=self.open_log_folder).pack(side='left', padx=4)
        self.btn_openpml = ttk.Button(top, text='PML Ac',
                                      command=self.open_pml,
                                      state='disabled')
        self.btn_openpml.pack(side='left', padx=4)
        ttk.Button(top, text='JSON',
                   command=self.save_json).pack(side='left', padx=4)
        ttk.Button(top, text='CSV',
                   command=self.save_csv).pack(side='left', padx=4)
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
        self.log_path_lbl = ttk.Label(stat, text='', foreground='#666')
        self.log_path_lbl.pack(side='right')

        guide = ttk.LabelFrame(root, text='NASIL KULLANILIR', padding=4)
        guide.pack(fill='x', padx=6, pady=(4, 0))
        ttk.Label(guide,
            text='1) Trace Baslat   '
                 '2) Photos\'ta Set As yap   '
                 '3) MARKER   '
                 '4) 20 sn bekle   '
                 '5) Durdur   '
                 '6) "PML Ac" ile manuel incele',
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

        wrap = ttk.Frame(root); wrap.pack(fill='both', expand=True, padx=6, pady=6)
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

    def spi_test(self):
        p = filedialog.askopenfilename(
            title='Wallpaper yapilacak resmi sec',
            initialdir=str(DESKTOP),
            filetypes=[('Resim', '*.jpg *.jpeg *.png *.bmp *.gif'),
                       ('Tumu', '*.*')])
        if not p: return
        self._emit_u(UEvent('System', 'Process', f'SPI Test: {p}', level='info'))
        try:
            ok = ctypes.windll.user32.SystemParametersInfoW(
                SPI_SETDESKWALLPAPER, 0, p,
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
            if ok:
                self._emit_u(UEvent('System', 'Process',
                    f'SPI Test BASARILI -> {p} (wallpaper degistirildi)',
                    level='info'))
                messagebox.showinfo('SPI Test',
                    f'BASARILI\n\nWallpaper set edildi:\n{p}\n\n'
                    'Bu demek: Windows API seviyesinde engel YOK. '
                    'Sorun sadece Photos uygulamasinda.')
            else:
                err = ctypes.get_last_error()
                self._emit_u(UEvent('System', 'Error',
                    f'SPI Test FAIL err={err} -> {p}', level='error'))
                messagebox.showerror('SPI Test',
                    f'BASARISIZ (err={err})\n\nWindows API seviyesinde '
                    f'engel var. Sorun tweak/policy.')
        except Exception as e:
            self._emit_u(UEvent('System', 'Error',
                f'SPI Test EXC -> {e}', level='error'))

    def open_pml(self):
        if not self.current_pml or not os.path.exists(self.current_pml):
            messagebox.showwarning('PML', 'PML dosyasi yok. Once trace yap.')
            return
        if not PROCMON_EXE:
            messagebox.showwarning('PML', 'Procmon64.exe bulunamadi.')
            return
        try:
            subprocess.Popen([PROCMON_EXE, '/OpenLog', self.current_pml],
                             creationflags=NO_WINDOW)
            self._emit_u(UEvent('System', 'Process',
                f'PML ProcMon GUI\'de aciliyor: {self.current_pml}',
                level='info'))
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
                f'# Bastard v7 ({SCRIPT_STEM}) - {datetime.now()}\n'
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
        try:
            while True:
                ev = self.queue.get_nowait()
                self.log.append(ev)
                self._write_live(ev)
                if self._passes(ev): self._write_event(ev)
                if ev.source in self.collector_labels:
                    self.collector_labels[ev.source].config(fg='green')
                if ev.source == 'ProcMon' and '->' in ev.details:
                    base = BASE_DIR
                    for f in os.listdir(base):
                        if f.startswith(SCRIPT_STEM) and f.endswith('.pml'):
                            self.current_pml = os.path.join(base, f)
                            try: self.btn_openpml.config(state='normal')
                            except Exception: pass
                            break
        except queue.Empty: pass
        self.root.after(60, self._drain)

    def _passes(self, ev):
        v = self.f_sources.get(ev.source)
        if v is not None and not v.get(): return False
        if self.f_err_only.get() and ev.level not in ('error', 'warn'): return False
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
        threading.Thread(target=self.tracer.start, daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_mark.config(state='normal')
        messagebox.showinfo('Bastard',
            'Trace basladi.\n\n'
            'ONEMLI: Once 10 sn Precheck sonuclarini oku.\n'
            'Sonra Photos\'ta Set As yap.\n'
            'Marker -> 20 sn -> Durdur.\n\n'
            'SPI Test butonu ile Photos\'u bypass edip test edebilirsin.')

    def mark(self):
        self._emit_u(UEvent('System', 'Marker',
            '>>> MARKER: Set As bu anda denendi <<<', level='error'))

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.btn_mark.config(state='disabled')
        self.root.after(12000, self._close_logfile)
        self.trace_start_ts = None

    def _on_close(self):
        self._save_geometry()
        try: self.tracer.stop()
        except Exception: pass
        time.sleep(0.5); self._close_logfile()
        self.root.destroy()

    def precheck(self):
        threading.Thread(target=lambda: DeepPrecheck(self._emit_u).run(),
                         daemon=True).start()

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
                self._emit_u(UEvent('System', 'Process', 'Bitti.', level='info'))
            except Exception as ex:
                self._emit_u(UEvent('System', 'Error', f'pip: {ex}', level='error'))
        threading.Thread(target=_run, daemon=True).start()

    def open_log_folder(self):
        try: os.startfile(str(DESKTOP))
        except Exception as ex: messagebox.showerror('Hata', str(ex))

    def save_json(self):
        p = filedialog.asksaveasfilename(defaultextension='.json',
                                         initialdir=str(DESKTOP),
                                         filetypes=[('JSON', '*.json')])
        if not p: return
        data = [{'ts': ev.ts.isoformat(), 'source': ev.source,
                 'type': ev.etype, 'pid': ev.pid, 'level': ev.level,
                 'details': ev.details} for ev in self.log]
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        messagebox.showinfo('OK', f'{len(data)} event')

    def save_csv(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv',
                                         initialdir=str(DESKTOP),
                                         filetypes=[('CSV', '*.csv')])
        if not p: return
        with open(p, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['timestamp', 'source', 'type', 'pid', 'level', 'details'])
            for ev in self.log:
                w.writerow([ev.ts.isoformat(), ev.source, ev.etype,
                            ev.pid or '', ev.level, ev.details])
        messagebox.showinfo('OK', f'{len(self.log)} event')

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