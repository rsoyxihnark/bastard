#!/usr/bin/env pythonw
# olayyeri_v2.pyw - Unified Windows Trace Toolkit (v2.2 FINAL)
# Tum fixler birlesik:
#  - Desktop canli log (SHGetKnownFolderPath ile dogru Desktop)
#  - WMICollector pythoncom.CoInitialize fix
#  - WMI registry watcher WQL fix (keyword args)
#  - Win32 hook devre disi (global hook DLL ister)
#  - ProcMon: benzersiz PML, eski PML temizligi, registry temizligi, graceful kill
#  - Bagimliliklari tek tikla kur butonu

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, sys, subprocess, queue, winreg, re, csv
import json, ctypes, atexit
from datetime import datetime
from pathlib import Path

# ---------- Opsiyonel bagimliliklar ----------
HAVE_PSUTIL = HAVE_WMI = HAVE_WIN32 = HAVE_ETW = HAVE_PROCMON_PARSER = False

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

NO_WINDOW = 0x08000000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------- Desktop bul (SHGetKnownFolderPath) ----------
def find_desktop():
    """SHGetKnownFolderPath(FOLDERID_Desktop) ile GERCEK Desktop'i bul.
    OneDrive yonlendirmesi / Turkce 'Masaustu' hepsi calisir."""
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
            result = Path(p.value)
            try: ctypes.windll.ole32.CoTaskMemFree(p)
            except Exception: pass
            if result.is_dir():
                return result
    except Exception:
        pass
    up = Path(os.environ.get('USERPROFILE', str(Path.home())))
    for c in (up / 'Desktop', up / 'OneDrive' / 'Desktop',
              up / 'OneDrive' / 'Masaüstü', up / 'Masaüstü'):
        if c.is_dir():
            return c
    return up

DESKTOP = find_desktop()


# ---------- ProcMon exe bul ----------
def find_procmon():
    cands = []
    for d in (BASE_DIR, str(DESKTOP), os.getcwd(), r'C:\Tools', r'C:\Sysinternals'):
        for name in ('Procmon64.exe', 'Procmon.exe', 'procmon64.exe', 'procmon.exe'):
            cands.append(os.path.join(d, name))
    for path in os.environ.get('PATH', '').split(os.pathsep):
        if not path: continue
        for name in ('Procmon64.exe', 'Procmon.exe'):
            cands.append(os.path.join(path, name))
    for c in cands:
        if os.path.exists(c):
            return c
    return None

PROCMON_EXE = find_procmon()


# ---------- Birlesik Event ----------
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
        ts = self.ts.strftime('%H:%M:%S.%f')[:-3]
        return f'{ts} [{self.source}] [{self.etype}] {self.details}'


# =================================================================
#  1. PROCMON COLLECTOR
# =================================================================
class ProcMonCollector(threading.Thread):
    def __init__(self, emit, base_dir):
        super().__init__(daemon=True)
        self.emit = emit
        self.base_dir = base_dir
        self.running = False
        self.proc = None
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pml_path = os.path.join(base_dir, f'trace_{ts}.pml')
        self.seen_hashes = set()

    def run(self):
        if not PROCMON_EXE:
            self.emit(UEvent('ProcMon', 'Error',
                'Procmon64.exe bulunamadi. Indir: '
                'https://download.sysinternals.com/files/ProcessMonitor.zip',
                level='error'))
            return
        if not HAVE_PROCMON_PARSER:
            self.emit(UEvent('ProcMon', 'Error',
                'procmon-parser YOK. PML yazilacak ama canli parse edilemeyecek. '
                'Kur: pip install procmon-parser', level='error'))

        self._cleanup_old_pmls()
        self._clear_procmon_registry()

        try:
            cmd = [PROCMON_EXE, '/AcceptEula', '/Quiet', '/Minimized',
                   '/BackingFile', self.pml_path]
            self.proc = subprocess.Popen(cmd, creationflags=NO_WINDOW,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL,
                                         cwd=self.base_dir)
            self.emit(UEvent('ProcMon', 'Process',
                f'ProcMon baslatildi -> {self.pml_path}', level='info'))
        except Exception as e:
            self.emit(UEvent('ProcMon', 'Error',
                f'ProcMon baslatilamadi: {e}', level='error'))
            return

        self.running = True
        if HAVE_PROCMON_PARSER:
            while self.running:
                time.sleep(2.5)
                try:
                    self._read_new_events()
                except Exception as e:
                    self.emit(UEvent('ProcMon', 'Error',
                        f'PML okuma hatasi: {e}', level='error'))
        else:
            while self.running:
                time.sleep(1.0)

        self._shutdown_procmon()

    def _cleanup_old_pmls(self):
        """Onceki calismalardan kalan trace_*.pml dosyalarini sil."""
        try:
            for f in os.listdir(self.base_dir):
                if f.lower().startswith('trace_') and f.lower().endswith('.pml'):
                    try:
                        os.remove(os.path.join(self.base_dir, f))
                        self.emit(UEvent('ProcMon', 'Process',
                            f'Eski trace silindi: {f}', level='info'))
                    except Exception:
                        pass
        except Exception:
            pass

    def _clear_procmon_registry(self):
        """ProcMon son backing-file yolunu registry'de sakliyor.
        Corrupt oldugu icin acilista dialog cikartiyor. Her baslangicta sil."""
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Sysinternals\Process Monitor', 0,
                winreg.KEY_ALL_ACCESS)
            for val in ('BackingFile', 'LastBackingFile'):
                try:
                    winreg.DeleteValue(k, val)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _shutdown_procmon(self):
        """Once yumusak (WM_CLOSE), sonra /F. Boylece PML duzgun kapanir."""
        if not self.proc:
            return
        try:
            if self.proc.poll() is None:
                subprocess.run(['taskkill', '/PID', str(self.proc.pid)],
                               capture_output=True, creationflags=NO_WINDOW,
                               timeout=5)
                try:
                    self.proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    subprocess.run(['taskkill', '/F', '/PID', str(self.proc.pid)],
                                   capture_output=True, creationflags=NO_WINDOW,
                                   timeout=5)
        except Exception:
            pass
        self.emit(UEvent('ProcMon', 'Process', 'ProcMon durduruldu.', level='info'))

    def _read_new_events(self):
        if not os.path.exists(self.pml_path):
            return
        try:
            with open(self.pml_path, 'rb') as f:
                reader = ProcmonLogsReader(f)
                for ev in reader:
                    op = getattr(ev, 'operation', None)
                    path = getattr(ev, 'path', None)
                    res = getattr(ev, 'result', None)
                    pid = getattr(ev, 'pid', None)
                    pname = getattr(ev, 'process_name', '?')
                    tod = getattr(ev, 'time_of_day', None)
                    key = (pname, pid, op, str(path), res, str(tod))
                    h = hash(key)
                    if h in self.seen_hashes:
                        continue
                    self.seen_hashes.add(h)

                    etype = self._classify_op(op)
                    if self._is_denied(res):
                        self.emit(UEvent('ProcMon', etype,
                            f'{op} {path} -> {res} (PID={pid} {pname})',
                            pid=pid, level='error'))
                    elif etype == 'Registry' and op and (
                            'Set' in op or 'Create' in op or 'Delete' in op):
                        self.emit(UEvent('ProcMon', 'Registry',
                            f'{op} {path} -> {res}', pid=pid, level='change'))
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
                                'QUERY', 'CLOSE', 'DELETE', 'RENAME', 'FILE')):
            return 'File'
        if 'TCP' in o or 'UDP' in o or 'SEND' in o or 'RECEIVE' in o:
            return 'Network'
        if 'PROCESS' in o or 'THREAD' in o:
            return 'Process'
        return 'Other'

    def stop(self):
        self.running = False


# =================================================================
#  2. ETW COLLECTOR
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

    def run(self):
        if not HAVE_ETW:
            self.emit(UEvent('ETW', 'Error',
                'pywintrace yok. Kur: pip install pywintrace', level='error'))
            return
        providers = []
        for name, guid in (('Kernel-Registry', self.KERNEL_REGISTRY),
                           ('Kernel-File', self.KERNEL_FILE),
                           ('Shell-Core', self.SHELL_CORE),
                           ('Immersive-Shell', self.IMMERSIVE_SHELL)):
            try:
                providers.append(etw_mod.ProviderInfo(name, etw_mod.GUID(guid)))
            except Exception as e:
                self.emit(UEvent('ETW', 'Error',
                    f'ProviderInfo {name}: {e}', level='error'))
        if not providers:
            return
        self.emit(UEvent('ETW', 'Process',
            f'{len(providers)} ETW provider baglaniyor...', level='info'))
        try:
            job = etw_mod.ETW(providers=providers,
                              event_callback=self._on_etw_event)
            job.start()
            self.sessions.append(job)
        except Exception as e:
            self.emit(UEvent('ETW', 'Error',
                f'ETW baslatilamadi: {e}', level='error'))
            return
        self.running = True
        while self.running:
            time.sleep(0.5)
        for s in self.sessions:
            try: s.stop()
            except Exception: pass
        self.emit(UEvent('ETW', 'Process',
            'ETW oturumlari kapatildi.', level='info'))

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
            etype = 'Registry' if 'registry' in str(provider).lower() else 'File'
            self.emit(UEvent('ETW', etype, detail, pid=pid, level=level))
        except Exception:
            pass

    def stop(self):
        self.running = False


# =================================================================
#  3. WMI COLLECTOR  (CoInitialize + WQL fix)
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
        try:
            pythoncom.CoInitialize()
        except Exception as e:
            self.emit(UEvent('WMI', 'Error',
                f'CoInitialize hatasi: {e}', level='error'))
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

            # WQL backslash escaping YOK. Keyword arguman guvenli.
            reg_keys = [
                ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallPaper'),
                ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallpaperStyle'),
                ('HKEY_CURRENT_USER',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers', None),
                ('HKEY_CURRENT_USER',
                 r'Software\Microsoft\Windows\CurrentVersion\Lock Screen', None),
                ('HKEY_CURRENT_USER',
                 r'Software\Microsoft\Windows\CurrentVersion\Themes', None),
            ]
            reg_ok = 0
            reg_fail = 0
            for hive, kp, vn in reg_keys:
                try:
                    if vn:
                        w = c.RegistryValueChangeEvent.watch_for(
                            Hive=hive, KeyPath=kp, ValueName=vn)
                    else:
                        w = c.RegistryKeyChangeEvent.watch_for(
                            Hive=hive, KeyPath=kp)
                    self.watchers.append(('reg', w))
                    reg_ok += 1
                except Exception:
                    reg_fail += 1
            if reg_ok:
                self.emit(UEvent('WMI', 'Process',
                    f'{reg_ok} WMI registry watcher aktif', level='info'))
            if reg_fail and not reg_ok:
                self.emit(UEvent('WMI', 'Process',
                    f'WMI registry event provider bu sistemde pasif '
                    f'({reg_fail} abone olamadi). Registry zaten ETW + ProcMon + '
                    f'polling ile izleniyor.', level='info'))

            self.running = True
            threads = []
            for kind, w in self.watchers:
                t = threading.Thread(target=self._watch_loop,
                                     args=(kind, w), daemon=True)
                t.start()
                threads.append(t)
            self.emit(UEvent('WMI', 'Process',
                f'{len(self.watchers)} WMI watcher aktif', level='info'))
            while self.running:
                time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def _watch_loop(self, kind, watcher):
        try:
            pythoncom.CoInitialize()
        except Exception:
            pass
        try:
            while self.running:
                try:
                    ev = watcher(timeout_ms=3000)
                    if kind == 'process':
                        pid = getattr(ev, 'ProcessId', None)
                        name = getattr(ev, 'Name', '?')
                        cmd = getattr(ev, 'CommandLine', '') or ''
                        self.emit(UEvent('WMI', 'Process',
                            f'Yeni process: {name} PID={pid} {cmd[:200]}',
                            pid=pid, level='info'))
                    else:
                        self.emit(UEvent('WMI', 'Registry',
                            f'Registry degisikligi: '
                            f'{getattr(ev, "KeyPath", "?")} '
                            f'{getattr(ev, "ValueName", "")} = '
                            f'{getattr(ev, "NewValue", "?")}',
                            level='change'))
                except Exception:
                    time.sleep(0.5)
        finally:
            try: pythoncom.CoUninitialize()
            except Exception: pass

    def stop(self):
        self.running = False


# =================================================================
#  4. PSUTIL COLLECTOR
# =================================================================
class PSUtilCollector(threading.Thread):
    TARGETS = ('photos.exe', 'runtimebroker.exe', 'dllhost.exe',
               'shellexperiencehost.exe', 'explorer.exe', 'sihost.exe',
               'startmenuexperiencehost.exe', 'searchhost.exe',
               'backgroundtaskhost.exe', 'applicationframehost.exe',
               'lockapp.exe', 'svchost.exe')
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.seen = set()

    def run(self):
        if not HAVE_PSUTIL:
            self.emit(UEvent('psutil', 'Error',
                'psutil yok. Kur: pip install psutil', level='error'))
            return
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
            try:
                n = (p.info.get('name') or '').lower()
                cmd = ' '.join(p.info.get('cmdline') or []) or (p.info.get('exe') or '')
                if n in self.TARGETS and self._interesting(n, cmd):
                    self.seen.add(p.pid)
                    self.emit(UEvent('psutil', 'Process',
                        f'MEVCUT: {p.info["name"]} PID={p.pid} '
                        f'PPID={p.info.get("ppid")} {cmd[:200]}',
                        pid=p.pid, level='info'))
            except Exception:
                pass

        self.running = True
        last_status_emit = 0
        while self.running:
            time.sleep(0.35)
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
                    if p.pid in self.seen:
                        continue
                    self.seen.add(p.pid)
                    try:
                        n = (p.info.get('name') or '').lower()
                        cmd = ' '.join(p.info.get('cmdline') or []) or (p.info.get('exe') or '')
                        if n in self.TARGETS and self._interesting(n, cmd):
                            self.emit(UEvent('psutil', 'Process',
                                f'YENI: {p.info["name"]} PID={p.pid} '
                                f'PPID={p.info.get("ppid")} {cmd[:200]}',
                                pid=p.pid, level='info'))
                    except Exception:
                        pass
            except Exception:
                pass
            if time.time() - last_status_emit > 5:
                last_status_emit = time.time()
                for p in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
                    try:
                        if (p.info.get('name') or '').lower() == 'photos.exe':
                            mi = p.info.get('memory_info')
                            rss = mi.rss // (1024 * 1024) if mi else 0
                            self.emit(UEvent('psutil', 'Process',
                                f'Photos durum: PID={p.pid} '
                                f'status={p.info.get("status")} RSS={rss}MB',
                                pid=p.pid, level='info'))
                    except Exception:
                        pass

    @staticmethod
    def _interesting(n, cmd):
        c = cmd.lower()
        if n in ('svchost.exe',):
            return 'themes' in c or 'appx' in c or 'state' in c
        return True

    def stop(self):
        self.running = False


# =================================================================
#  5. WIN32 COLLECTOR (sadece EventLog; hook devre disi)
# =================================================================
class Win32Collector(threading.Thread):
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False

    def run(self):
        self.running = True
        self.emit(UEvent('Win32', 'Process',
            'Win32 hook devre disi (global hook DLL ister, EventLog aktif)',
            level='info'))
        t = threading.Thread(target=self._eventlog_loop, daemon=True)
        t.start()
        while self.running:
            time.sleep(0.5)

    def _eventlog_loop(self):
        if not HAVE_WIN32:
            self.emit(UEvent('Win32', 'Error',
                'pywin32 yok. Kur: pip install pywin32', level='error'))
            return
        last_records = {}
        channels = ('Application', 'System')
        for ch in channels:
            try:
                h = win32evtlog.OpenEventLog(None, ch)
                flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                         win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                evs = win32evtlog.ReadEventLog(h, flags, 0)
                if evs:
                    last_records[ch] = evs[0].RecordNumber
                win32evtlog.CloseEventLog(h)
            except Exception:
                pass
        self.emit(UEvent('Win32', 'Log',
            'EventLog takibi basladi', level='info'))

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
                    if not evs:
                        continue
                    maxrec = last
                    for ev in evs:
                        if ev.RecordNumber <= last:
                            continue
                        maxrec = max(maxrec, ev.RecordNumber)
                        etype = ev.EventType
                        if etype not in (win32con.EVENTLOG_ERROR_TYPE,
                                         win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = ('error' if etype == win32con.EVENTLOG_ERROR_TYPE
                               else 'warn')
                        try:
                            msg = ' | '.join(ev.StringInserts) if ev.StringInserts else ''
                        except Exception:
                            msg = ''
                        if len(msg) > 400:
                            msg = msg[:400] + '...'
                        self.emit(UEvent('EvtLog', 'Log',
                            f'[{ch}] {ev.SourceName} '
                            f'ID={ev.EventID & 0xFFFF} {msg}',
                            level=lvl))
                    last_records[ch] = maxrec
                except Exception:
                    pass
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
        if self.running:
            return
        self.running = True
        self.start_time = datetime.now()

        missing = []
        if not HAVE_PSUTIL: missing.append('psutil')
        if not HAVE_WMI: missing.append('wmi')
        if not HAVE_WIN32: missing.append('pywin32')
        if not HAVE_ETW: missing.append('pywintrace')
        if not HAVE_PROCMON_PARSER: missing.append('procmon-parser')

        self.emit(UEvent('System', 'Process',
            f'=== BIRLESIK TRACE BASLADI === {self.start_time}', level='info'))
        self.emit(UEvent('System', 'Process',
            f'Desktop: {DESKTOP}', level='info'))
        if PROCMON_EXE:
            self.emit(UEvent('System', 'Process',
                f'ProcMon: {PROCMON_EXE}', level='info'))
        else:
            self.emit(UEvent('System', 'Error',
                'Procmon64.exe bulunamadi. Indir: '
                'https://download.sysinternals.com/files/ProcessMonitor.zip',
                level='error'))
        if missing:
            self.emit(UEvent('System', 'Error',
                f'Eksik pip paketleri: {", ".join(missing)} '
                f'(ust bardan "Bagimliliklari Kur" tikla)', level='error'))

        collectors = []
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
        for c in collectors:
            c.start()
            self.emit(UEvent('System', 'Process',
                f'{c.__class__.__name__} baslatildi', level='info'))

        self.emit(UEvent('System', 'Process',
            f'Toplam {len(collectors)} collector aktif. '
            f'Simdi sorunu tekrar uret.', level='info'))

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.emit(UEvent('System', 'Process',
            'Trace durduruluyor...', level='info'))
        for c in self.collectors:
            try: c.stop()
            except Exception: pass
        for c in self.collectors:
            try:
                if c.is_alive():
                    c.join(timeout=3)
            except Exception:
                pass
        self.emit(UEvent('System', 'Process',
            f'=== TRACE BITTI === {datetime.now()} '
            f'(sure: {datetime.now() - self.start_time})', level='info'))


# =================================================================
#  GUI
# =================================================================
class App:
    SOURCES = {
        'ProcMon': {'label': 'ProcMon', 'color': '#ff9f43'},
        'ETW': {'label': 'ETW', 'color': '#54a0ff'},
        'WMI': {'label': 'WMI', 'color': '#5f27cd'},
        'psutil': {'label': 'psutil', 'color': '#10ac84'},
        'Win32': {'label': 'Win32', 'color': '#c8d6e5'},
        'EvtLog': {'label': 'EvtLog', 'color': '#ee5253'},
        'System': {'label': 'System', 'color': '#8395a7'},
    }
    ETYPES = {
        'Process': '#7ec8ff', 'Registry': '#f0c060', 'File': '#a4e400',
        'Network': '#ff9ff3', 'Hook': '#c8d6e5', 'Log': '#ff6b6b',
        'Error': '#ff6b6b', 'Unknown': '#dcdcdc',
    }

    def __init__(self, root):
        self.root = root
        root.title('Olay Yeri Inceleme v2.2 FINAL')
        root.geometry('1400x860')

        self.queue = queue.Queue()
        self.tracer = UnifiedTracer(self._emit_u)
        self.log = []
        self.live_log_fh = None
        self.live_log_path = None

        # ---- Ust Bar ----
        top = ttk.Frame(root, padding=6); top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='\u25b6 Trace Baslat',
                                    command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='\u25a0 Durdur',
                                   command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f50d On Kontrol',
                   command=self.precheck).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4e6 Bagimliliklari Kur',
                   command=self.install_deps).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4c2 Log Klasoru',
                   command=self.open_log_folder).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4be JSON',
                   command=self.save_json).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4be CSV',
                   command=self.save_csv).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f5d1 Temizle',
                   command=self.clear).pack(side='left', padx=4)

        self.status = ttk.Label(top, text=f'Desktop: {DESKTOP}', foreground='gray')
        self.status.pack(side='right')

        # ---- Collector durum ----
        stat = ttk.Frame(root, padding=(6, 0)); stat.pack(fill='x')
        self.collector_labels = {}
        for src, meta in self.SOURCES.items():
            if src == 'System':
                continue
            lbl = tk.Label(stat, text=f'\u25cf {meta["label"]}', fg='gray',
                           font=('Segoe UI', 8, 'bold'))
            lbl.pack(side='left', padx=4)
            self.collector_labels[src] = lbl
        self.log_path_lbl = ttk.Label(stat, text='', foreground='#666')
        self.log_path_lbl.pack(side='right')

        # ---- Filtre ----
        filt = ttk.LabelFrame(root, text='Filtre', padding=6)
        filt.pack(fill='x', padx=6, pady=(4, 0))
        self.f_sources = {}
        for src, meta in self.SOURCES.items():
            var = tk.BooleanVar(value=True)
            self.f_sources[src] = var
            ttk.Checkbutton(filt, text=meta['label'], variable=var,
                            command=self.refilter).pack(side='left', padx=2)
        ttk.Separator(filt, orient='vertical').pack(side='left', fill='y', padx=8)
        self.f_types = {}
        for et in self.ETYPES:
            var = tk.BooleanVar(value=True)
            self.f_types[et] = var
            ttk.Checkbutton(filt, text=et, variable=var,
                            command=self.refilter).pack(side='left', padx=2)
        ttk.Separator(filt, orient='vertical').pack(side='left', fill='y', padx=8)
        self.f_err_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text='Sadece Hata', variable=self.f_err_only,
                        command=self.refilter).pack(side='left', padx=2)
        ttk.Label(filt, text='Ara:').pack(side='left', padx=(8, 0))
        self.f_search = tk.StringVar()
        ent = ttk.Entry(filt, textvariable=self.f_search, width=22)
        ent.pack(side='left', padx=4)
        ent.bind('<KeyRelease>', lambda e: self.refilter())

        # ---- Log ----
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

        root.protocol('WM_DELETE_WINDOW', self._on_close)
        atexit.register(self._close_logfile)
        root.after(60, self._drain)

    # ---- Live log ----
    def _open_logfile(self):
        self._close_logfile()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.live_log_path = DESKTOP / f'olayyeri_{ts}.log'
        try:
            self.live_log_fh = open(self.live_log_path, 'w', encoding='utf-8')
            self.live_log_fh.write(
                f'# Olay Yeri Inceleme v2.2 FINAL - {datetime.now()}\n')
            self.live_log_fh.write(f'# Log: {self.live_log_path}\n')
            self.live_log_fh.flush()
            self.log_path_lbl.config(text=f'Log: {self.live_log_path.name}')
            self.status.config(text=f'Log -> {self.live_log_path}',
                               foreground='gray')
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
            except Exception:
                pass
            self.live_log_fh = None

    def _write_live(self, uevent):
        if not self.live_log_fh:
            return
        try:
            self.live_log_fh.write(uevent.to_log_line() + '\n')
            self.live_log_fh.flush()
        except Exception:
            pass

    # ---- Event queue ----
    def _emit_u(self, uevent):
        self.queue.put(uevent)

    def _drain(self):
        try:
            while True:
                ev = self.queue.get_nowait()
                self.log.append(ev)
                self._write_live(ev)
                if self._passes(ev):
                    self._write_event(ev)
                if ev.source in self.collector_labels and ev.etype != 'Error':
                    self.collector_labels[ev.source].config(fg='green')
        except queue.Empty:
            pass
        self.root.after(60, self._drain)

    def _passes(self, ev):
        v = self.f_sources.get(ev.source)
        if v is not None and not v.get():
            return False
        v = self.f_types.get(ev.etype)
        if v is not None and not v.get():
            return False
        if self.f_err_only.get() and ev.level not in ('error', 'warn'):
            return False
        q = self.f_search.get().lower()
        if q and q not in ev.details.lower():
            return False
        return True

    def _write_event(self, ev):
        ts = ev.ts.strftime('%H:%M:%S.%f')[:-3]
        src = f'[{ev.source}]'
        et = f'[{ev.etype}]'
        tag = ('error' if ev.level == 'error' else
               'warn' if ev.level == 'warn' else
               'change' if ev.level == 'change' else 'info')
        self.txt.insert('end', f'{ts} ', 'info')
        self.txt.insert('end', f'{src:<9} ', f'src_{ev.source}')
        self.txt.insert('end', f'{et:<10} ', f'type_{ev.etype}')
        self.txt.insert('end', f'{ev.details}\n', tag)
        self.txt.see('end')

    def refilter(self):
        self.txt.delete('1.0', 'end')
        for ev in self.log:
            if self._passes(ev):
                self._write_event(ev)

    # ---- Actions ----
    def start(self):
        self._open_logfile()
        threading.Thread(target=self.tracer.start, daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.status.config(
            text=f'CALISIYOR | Log -> {self.live_log_path}',
            foreground='green')

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.status.config(
            text=f'DURDURULDU | Log -> {self.live_log_path}',
            foreground='orange')
        self.root.after(4000, self._close_logfile)

    def _on_close(self):
        try:
            self.tracer.stop()
        except Exception:
            pass
        time.sleep(0.3)
        self._close_logfile()
        self.root.destroy()

    def precheck(self):
        threading.Thread(target=self._precheck_worker, daemon=True).start()

    def _precheck_worker(self):
        def e(d): self._emit_u(UEvent('System', 'Error', d, level='error'))
        def i(d): self._emit_u(UEvent('System', 'Process', d, level='info'))
        i('========== ON KONTROL v2.2 ==========')
        i(f'Desktop: {DESKTOP}')
        if PROCMON_EXE:
            i(f'ProcMon: {PROCMON_EXE}')
        else:
            e('ProcMon: YOK. '
              'https://download.sysinternals.com/files/ProcessMonitor.zip')
        for name, ok in (('psutil', HAVE_PSUTIL), ('wmi', HAVE_WMI),
                         ('pywin32', HAVE_WIN32), ('pywintrace', HAVE_ETW),
                         ('procmon-parser', HAVE_PROCMON_PARSER)):
            if ok:
                i(f'{name}: OK')
            else:
                e(f'{name}: YOK -> pip install {name}')

        hive_map = {'HKCU': winreg.HKEY_CURRENT_USER,
                    'HKLM': winreg.HKEY_LOCAL_MACHINE}
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
        i('[Policy Kontrolu]')
        found = False
        for hive, path, name in pol:
            try:
                k = winreg.OpenKey(hive_map[hive], path)
                v, _ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                e(f'  >> POLITIKA: {hive}\\{path}\\{name} = {v}')
                found = True
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if not found:
            i('  Politika key bulunamadi (iyi haber)')

        i('[Servisler]')
        if HAVE_PSUTIL:
            for svc in ('Themes', 'AppXSvc', 'ClipSVC', 'StateRepository',
                        'TokenBroker', 'Dwm', 'UxSms', 'ShellHWDetection'):
                try:
                    s = psutil.win_service_get(svc)
                    d = s.as_dict()
                    if (d.get('status') != 'running' or
                            d.get('start_type') == 'disabled'):
                        e(f'  >> SORUNLU: {svc} status={d.get("status")} '
                          f'start={d.get("start_type")}')
                    else:
                        i(f'  OK: {svc}')
                except Exception as ex:
                    e(f'  >> Servis yok: {svc} ({ex})')

        i('[Wallpaper Dosya]')
        ad = os.environ.get('APPDATA', '')
        wp = os.path.join(ad, 'Microsoft', 'Windows', 'Themes',
                          'TranscodedWallpaper')
        if os.path.exists(wp):
            try:
                with open(wp, 'ab'):
                    pass
                i(f'  OK yazilabilir: {wp}')
            except Exception as ex:
                e(f'  >> YAZILAMAZ: {wp} -> {ex}')
        else:
            i(f'  Dosya yok (normal): {wp}')
        i('========== ON KONTROL BITTI ==========')

    def install_deps(self):
        if not messagebox.askyesno(
                'Bagimlilik Kurulumu',
                'Su paketler kurulacak:\n'
                '  psutil, wmi, pywin32, pywintrace, procmon-parser\n\n'
                'Devam edilsin mi?'):
            return

        def _run():
            try:
                p = subprocess.Popen(
                    [sys.executable, '-m', 'pip', 'install', '--upgrade',
                     'psutil', 'wmi', 'pywin32', 'pywintrace', 'procmon-parser'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    creationflags=NO_WINDOW, text=True)
                for line in p.stdout:
                    self._emit_u(UEvent('System', 'Process',
                        f'[pip] {line.rstrip()}', level='info'))
                p.wait()
                self._emit_u(UEvent('System', 'Process',
                    'Kurulum bitti. Uygulamayi yeniden baslat.', level='info'))
            except Exception as e:
                self._emit_u(UEvent('System', 'Error',
                    f'pip hatasi: {e}', level='error'))
        threading.Thread(target=_run, daemon=True).start()

    def open_log_folder(self):
        try:
            os.startfile(str(DESKTOP))
        except Exception as e:
            messagebox.showerror('Acilamadi', str(e))

    def save_json(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.json', initialdir=str(DESKTOP),
            filetypes=[('JSON', '*.json')])
        if not p:
            return
        data = [{'ts': ev.ts.isoformat(), 'source': ev.source,
                 'type': ev.etype, 'pid': ev.pid,
                 'level': ev.level, 'details': ev.details}
                for ev in self.log]
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        messagebox.showinfo('Kaydedildi', f'{len(data)} event -> {p}')

    def save_csv(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.csv', initialdir=str(DESKTOP),
            filetypes=[('CSV', '*.csv')])
        if not p:
            return
        with open(p, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['timestamp', 'source', 'type', 'pid', 'level', 'details'])
            for ev in self.log:
                w.writerow([ev.ts.isoformat(), ev.source, ev.etype,
                            ev.pid or '', ev.level, ev.details])
        messagebox.showinfo('Kaydedildi', f'{len(self.log)} event -> {p}')

    def clear(self):
        self.log.clear()
        self.txt.delete('1.0', 'end')


def main():
    root = tk.Tk()
    try:
        root.call('tk', 'scaling', 1.1)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == '__main__':
    main()