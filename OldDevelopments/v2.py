#!/usr/bin/env pythonw
# olayyeri_v2.pyw - Unified Windows Trace Toolkit
# Ahtapot: ProcMon + ETW + WMI + psutil + pywin32 + Win32 hooks
# Tek tepside kronolojik birlesik event stream.

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, sys, subprocess, queue, winreg, re, csv
import json, hashlib, ctypes
from datetime import datetime
from pathlib import Path

# ---------- Opsiyonel bagimliliklar ----------
HAVE_PSUTIL = HAVE_WMI = HAVE_WIN32 = HAVE_ETW = HAVE_PROCMON_PARSER = False

try:
    import psutil; HAVE_PSUTIL = True
except ImportError: pass
try:
    import wmi; HAVE_WMI = True
except ImportError: pass
try:
    import win32evtlog, win32evtlogutil, win32con, win32api
    import win32security; HAVE_WIN32 = True
except ImportError: pass
try:
    import etw as etw_mod; HAVE_ETW = True
except ImportError: pass
try:
    from procmon_parser import ProcmonLogsReader, parse_pml
    HAVE_PROCMON_PARSER = True
except ImportError: pass

NO_WINDOW = 0x08000000
CREATE_NEW_CONSOLE = 0x00000010

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROCMON_EXE = None
for cand in ('Procmon64.exe', 'Procmon.exe', 'procmon64.exe', 'procmon.exe'):
    p = os.path.join(BASE_DIR, cand)
    if os.path.exists(p):
        PROCMON_EXE = p; break

# ---------- Birlesik Event ----------
class UEvent:
    __slots__ = ('ts','source','etype','pid','details','level','raw')
    def __init__(self, source, etype, details, pid=None, level='info', raw=None):
        self.ts = datetime.now()
        self.source = source      # ProcMon | ETW | WMI | psutil | Win32 | EvtLog
        self.etype  = etype       # Process | Registry | File | Network | Hook | Log | Error
        self.pid    = pid
        self.details= details
        self.level  = level       # info | warn | error | change
        self.raw    = raw
    def __repr__(self):
        return f'[{self.ts.strftime("%H:%M:%S.%f")[:-3]}] [{self.source}/{self.etype}] {self.details}'


# =================================================================
#  1. PROCMON COLLECTOR
# =================================================================
class ProcMonCollector(threading.Thread):
    """ProcMon'u /BackingFile ile baslatir, PML dosyasini periyodik okur."""
    def __init__(self, emit, base_dir):
        super().__init__(daemon=True)
        self.emit = emit
        self.base_dir = base_dir
        self.running = False
        self.proc = None
        self.pml_path = os.path.join(base_dir, 'trace.pml')
        self.seen_hashes = set()
        self.last_offset = 0
        self.lock = threading.Lock()

    def run(self):
        if not PROCMON_EXE:
            self.emit(UEvent('ProcMon','Error','Procmon64.exe bulunamadi! Ayni klasore koy.',level='error'))
            return
        if not HAVE_PROCMON_PARSER:
            self.emit(UEvent('ProcMon','Error',
                'procmon-parser yok. "pip install procmon-parser"', level='error'))
            return
        # Baslat
        try:
            if os.path.exists(self.pml_path):
                os.remove(self.pml_path)
            cmd = [PROCMON_EXE, '/AcceptEula', '/Quiet', '/Minimized',
                   '/BackingFile', self.pml_path, '/NoFilter']
            self.proc = subprocess.Popen(cmd, creationflags=NO_WINDOW,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            self.emit(UEvent('ProcMon','Process',
                f'ProcMon baslatildi: {os.path.basename(PROCMON_EXE)}', level='info'))
        except Exception as e:
            self.emit(UEvent('ProcMon','Error', f'ProcMon baslatilamadi: {e}', level='error'))
            return

        self.running = True
        # PML'i periyodik oku
        while self.running:
            time.sleep(2.5)
            try:
                self._read_new_events()
            except Exception as e:
                self.emit(UEvent('ProcMon','Error', f'PML okuma hatasi: {e}', level='error'))

        # Durdur
        try:
            if self.proc and self.proc.poll() is None:
                subprocess.run(['taskkill','/F','/PID',str(self.proc.pid)],
                               capture_output=True, creationflags=NO_WINDOW)
        except Exception: pass
        self.emit(UEvent('ProcMon','Process','ProcMon durduruldu.', level='info'))

    def _read_new_events(self):
        if not os.path.exists(self.pml_path):
            return
        try:
            with open(self.pml_path, 'rb') as f:
                reader = ProcmonLogsReader(f)
                for ev in reader:
                    # Her event'ten bir hash uret (tekrarini engelle)
                    key = (ev.process_name, ev.pid, ev.operation,
                           str(ev.path), ev.result, str(ev.time_of_day))
                    h = hash(key)
                    if h in self.seen_hashes:
                        continue
                    self.seen_hashes.add(h)

                    etype = self._classify_op(ev.operation)
                    level = 'error' if self._is_denied(ev.result) else 'info'
                    if level == 'error':
                        self.emit(UEvent('ProcMon', etype,
                            f'{ev.operation} {ev.path} -> {ev.result} '
                            f'(PID={ev.pid} {ev.process_name})',
                            pid=ev.pid, level='error'))
                    elif etype == 'Registry' and 'Set' in (ev.operation or ''):
                        self.emit(UEvent('ProcMon', 'Registry',
                            f'{ev.operation} {ev.path} -> {ev.result}',
                            pid=ev.pid, level='change'))
        except Exception:
            pass  # PML hala yaziliyor olabilir

    @staticmethod
    def _is_denied(result):
        if not result: return False
        r = result.lower()
        return ('access denied' in r or 'erişim engellendi' in r
                or 'privilege not held' in r or 'reparse' in r and 'denied' in r)

    @staticmethod
    def _classify_op(op):
        if not op: return 'Unknown'
        o = op.upper()
        if 'REG' in o or 'REGISTRY' in o: return 'Registry'
        if any(k in o for k in ('CREATE','WRITE','READ','SETINFO',
                                'QUERY','CLOSE','DELETE','RENAME')): return 'File'
        if 'TCP' in o or 'UDP' in o or 'SEND' in o or 'RECEIVE' in o: return 'Network'
        if 'PROCESS' in o or 'THREAD' in o: return 'Process'
        return 'Other'

    def stop(self):
        self.running = False
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


# =================================================================
#  2. ETW COLLECTOR (pywintrace)
# =================================================================
class ETWCollector(threading.Thread):
    """Microsoft-Windows-Kernel-Registry + Kernel-File ETW oturumlarini dinler."""
    # Bilinen Provider GUID'leri
    KERNEL_REGISTRY = '{70EB4F03-C1DE-4F73-A051-33D13D541355}'
    KERNEL_FILE     = '{EDD08927-9CC4-4E65-B970-C2560FB5C289}'
    SHELL_CORE      = '{30336ED4-E327-447C-9DE0-51B2E6059F02}'
    IMMERSIVE_SHELL = '{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}'

    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.sessions = []
        self.lock = threading.Lock()

    def run(self):
        if not HAVE_ETW:
            self.emit(UEvent('ETW','Error','pywintrace yok. "pip install pywintrace"', level='error'))
            return

        providers = []
        for name, guid in (('Kernel-Registry', self.KERNEL_REGISTRY),
                           ('Kernel-File', self.KERNEL_FILE),
                           ('Shell-Core', self.SHELL_CORE),
                           ('Immersive-Shell', self.IMMERSIVE_SHELL)):
            try:
                providers.append(etw_mod.ProviderInfo(name, etw_mod.GUID(guid)))
            except Exception as e:
                self.emit(UEvent('ETW','Error', f'ProviderInfo hatasi {name}: {e}', level='error'))

        if not providers:
            return

        self.emit(UEvent('ETW','Process',
            f'{len(providers)} ETW provider baglaniyor...', level='info'))

        try:
            job = etw_mod.ETW(providers=providers,
                              event_callback=self._on_etw_event)
            job.start()
            self.sessions.append(job)
        except Exception as e:
            self.emit(UEvent('ETW','Error', f'ETW baslatilamadi: {e}', level='error'))
            return

        self.running = True
        while self.running:
            time.sleep(0.5)

        for s in self.sessions:
            try: s.stop()
            except Exception: pass
        self.emit(UEvent('ETW','Process','ETW oturumlari kapatildi.', level='info'))

    def _on_etw_event(self, event):
        try:
            provider = getattr(event, 'provider_name', '?')
            eid = getattr(event, 'event_id', None)
            pid = getattr(event, 'process_id', None)
            payload = getattr(event, 'payload', None)

            # Payload'dan anlamli alanlar cikar
            details_parts = []
            if payload:
                if isinstance(payload, dict):
                    for k, v in list(payload.items())[:6]:
                        if v is not None and str(v).strip():
                            details_parts.append(f'{k}={v}')
                else:
                    s = str(payload)
                    if len(s) > 300: s = s[:300] + '...'
                    details_parts.append(s)

            detail = f'[{provider}] EID={eid} ' + ' | '.join(details_parts)

            level = 'info'
            low = detail.lower()
            if ('denied' in low or 'erişim engellendi' in low
                    or '0x80070005' in low or 'access_denied' in low):
                level = 'error'
            elif eid in (1, 2, 3, 11, 12, 13):  # registry/file create/write
                level = 'change'

            self.emit(UEvent('ETW', 'Registry' if 'registry' in provider.lower() else 'File',
                             detail, pid=pid, level=level))
        except Exception:
            pass

    def stop(self):
        self.running = False


# =================================================================
#  3. WMI COLLECTOR
# =================================================================
class WMICollector(threading.Thread):
    """WMI ile process olusturma + registry degisikligi olaylari."""
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.watchers = []

    def run(self):
        if not HAVE_WMI:
            self.emit(UEvent('WMI','Error','wmi yok. "pip install wmi"', level='error'))
            return
        try:
            c = wmi.WMI()
        except Exception as e:
            self.emit(UEvent('WMI','Error', f'WMI baglanamadi: {e}', level='error'))
            return

        # Process creation
        try:
            pw = c.Win32_Process.watch_for('creation')
            self.watchers.append(('process', pw))
            self.emit(UEvent('WMI','Process','Process creation watcher aktif', level='info'))
        except Exception as e:
            self.emit(UEvent('WMI','Error', f'Process watcher: {e}', level='error'))

        # Registry degisikligi (duvar kagidi ile ilgili keyler)
        reg_keys = [
            ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallPaper'),
            ('HKEY_CURRENT_USER', r'Control Panel\Desktop', 'WallpaperStyle'),
            ('HKEY_CURRENT_USER', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers', None),
            ('HKEY_CURRENT_USER', r'Software\Microsoft\Windows\CurrentVersion\Lock Screen', None),
            ('HKEY_CURRENT_USER', r'Software\Microsoft\Windows\CurrentVersion\Themes', None),
            ('HKEY_LOCAL_MACHINE', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', None),
        ]
        for hive, kp, vn in reg_keys:
            try:
                if vn:
                    wql = (f"SELECT * FROM RegistryValueChangeEvent WHERE "
                           f"Hive='{hive}' AND KeyPath='{kp.replace(chr(92), chr(92)*2)}' "
                           f"AND ValueName='{vn}'")
                else:
                    wql = (f"SELECT * FROM RegistryTreeChangeEvent WHERE "
                           f"Hive='{hive}' AND RootPath='{kp.replace(chr(92), chr(92)*2)}'")
                w = c.watch_for(raw_wql=wql)
                self.watchers.append(('reg', w))
                self.emit(UEvent('WMI','Registry', f'Registry watcher: {hive}\\{kp}', level='info'))
            except Exception as e:
                self.emit(UEvent('WMI','Error', f'Registry watcher {kp}: {e}', level='error'))

        self.running = True
        threads = []
        for kind, w in self.watchers:
            t = threading.Thread(target=self._watch_loop, args=(kind, w), daemon=True)
            t.start(); threads.append(t)

        while self.running:
            time.sleep(0.5)

    def _watch_loop(self, kind, watcher):
        while self.running:
            try:
                ev = watcher(timeout_ms=3000)
                if kind == 'process':
                    pid = getattr(ev, 'ProcessId', None)
                    name = getattr(ev, 'Name', '?')
                    cmd = getattr(ev, 'CommandLine', '') or ''
                    self.emit(UEvent('WMI','Process',
                        f'Yeni process: {name} PID={pid} {cmd[:200]}',
                        pid=pid, level='info'))
                else:
                    self.emit(UEvent('WMI','Registry',
                        f'Registry degisikligi: {getattr(ev, "KeyPath", "?")} '
                        f'{getattr(ev, "ValueName", "")} = {getattr(ev, "NewValue", "?")}',
                        level='change'))
            except Exception:
                # timeout veya COM hatasi -> devam
                time.sleep(0.5)

    def stop(self):
        self.running = False


# =================================================================
#  4. PSUTIL COLLECTOR
# =================================================================
class PSUtilCollector(threading.Thread):
    """psutil ile process yasam dongusu + sistem kaynaklari."""
    TARGETS = ('photos.exe','runtimebroker.exe','dllhost.exe',
               'shellexperiencehost.exe','explorer.exe','sihost.exe',
               'startmenuexperiencehost.exe','searchhost.exe',
               'backgroundtaskhost.exe','applicationframehost.exe')
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.seen = set()

    def run(self):
        if not HAVE_PSUTIL:
            self.emit(UEvent('psutil','Error','psutil yok. "pip install psutil"', level='error'))
            return
        # Mevcut hedef processleri raporla
        for p in psutil.process_iter(['pid','name','exe','cmdline','ppid']):
            try:
                n = (p.info.get('name') or '').lower()
                if n in self.TARGETS:
                    self.seen.add(p.pid)
                    self.emit(UEvent('psutil','Process',
                        f'MEVCUT: {p.info["name"]} PID={p.pid} PPID={p.info.get("ppid")} '
                        f'{(p.info.get("exe") or "")[:150]}',
                        pid=p.pid, level='info'))
            except Exception: pass

        self.running = True
        while self.running:
            time.sleep(0.35)
            try:
                for p in psutil.process_iter(['pid','name','exe','cmdline','ppid']):
                    if p.pid in self.seen: continue
                    self.seen.add(p.pid)
                    try:
                        n = (p.info.get('name') or '').lower()
                        cmd = ' '.join(p.info.get('cmdline') or []) or (p.info.get('exe') or '')
                        if n in self.TARGETS:
                            self.emit(UEvent('psutil','Process',
                                f'YENI: {p.info["name"]} PID={p.pid} PPID={p.info.get("ppid")} {cmd[:250]}',
                                pid=p.pid, level='info'))
                        elif any(k in cmd.lower() for k in ('wallpaper','theme','lockscreen','personaliz')):
                            self.emit(UEvent('psutil','Process',
                                f'ILGILI: {p.info["name"]} PID={p.pid} {cmd[:250]}',
                                pid=p.pid, level='info'))
                    except Exception: pass
            except Exception: pass

            # periyodik hedef process durum kontrolu
            try:
                for p in psutil.process_iter(['pid','name','status','cpu_percent','memory_info']):
                    try:
                        if (p.info.get('name') or '').lower() == 'photos.exe':
                            mi = p.info.get('memory_info')
                            rss = mi.rss // (1024*1024) if mi else 0
                            self.emit(UEvent('psutil','Process',
                                f'Photos durum: PID={p.pid} status={p.info.get("status")} '
                                f'RSS={rss}MB CPU={p.info.get("cpu_percent")}%',
                                pid=p.pid, level='info'))
                    except Exception: pass
            except Exception: pass
            time.sleep(4.0)  # durum raporu 4 sn'de bir

    def stop(self):
        self.running = False


# =================================================================
#  5. WIN32 COLLECTOR (EventLog + API Hooks)
# =================================================================
class Win32Collector(threading.Thread):
    """EventLog okuma + basit Win32 API hook'lari (SetWindowsHookEx)."""
    def __init__(self, emit):
        super().__init__(daemon=True)
        self.emit = emit
        self.running = False
        self.hooks = []

    def run(self):
        self.running = True
        # EventLog tarayici
        t_evt = threading.Thread(target=self._eventlog_loop, daemon=True)
        t_evt.start()
        # Win32 hook ornegi (WH_CALLWNDPROCRET - pencere mesajlari)
        if HAVE_WIN32:
            try:
                self._install_hook()
            except Exception as e:
                self.emit(UEvent('Win32','Hook', f'Hook kurulamadi: {e}', level='error'))
        while self.running:
            time.sleep(0.5)

    def _eventlog_loop(self):
        if not HAVE_WIN32:
            self.emit(UEvent('Win32','Error','pywin32 yok. "pip install pywin32"', level='error'))
            return
        # Son okunan kayit numaralarini takip et
        last_records = {}
        channels = ('Application', 'System')
        # ilk gecis: sadece son 20 kaydi al
        for ch in channels:
            try:
                h = win32evtlog.OpenEventLog(None, ch)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                evs = win32evtlog.ReadEventLog(h, flags, 0)
                if evs:
                    last_records[ch] = evs[0].RecordNumber
                win32evtlog.CloseEventLog(h)
            except Exception: pass
        self.emit(UEvent('Win32','Log','EventLog takibi basladi', level='info'))

        while self.running:
            time.sleep(2.0)
            for ch in channels:
                try:
                    h = win32evtlog.OpenEventLog(None, ch)
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    last = last_records.get(ch, 0)
                    evs = win32evtlog.ReadEventLog(h, flags, 0)
                    if not evs:
                        win32evtlog.CloseEventLog(h); continue
                    maxrec = last
                    for ev in evs:
                        if ev.RecordNumber <= last: continue
                        maxrec = max(maxrec, ev.RecordNumber)
                        # Sadece Error(1)/Warning(2) seviyelerini al
                        etype = ev.EventType
                        if etype not in (win32con.EVENTLOG_ERROR_TYPE,
                                         win32con.EVENTLOG_WARNING_TYPE):
                            continue
                        lvl = 'error' if etype == win32con.EVENTLOG_ERROR_TYPE else 'warn'
                        msg = ' | '.join(ev.StringInserts) if ev.StringInserts else ''
                        if len(msg) > 400: msg = msg[:400] + '...'
                        self.emit(UEvent('EvtLog','Log',
                            f'[{ch}] {ev.SourceName} ID={ev.EventID & 0xFFFF} {msg}',
                            level=lvl))
                    last_records[ch] = maxrec
                    win32evtlog.CloseEventLog(h)
                except Exception:
                    try: win32evtlog.CloseEventLog(h)
                    except Exception: pass

    def _install_hook(self):
        """WH_CALLWNDPROCRET ile ust seviye pencere mesaji hook'u.
        Not: Bu hook kendi process'imizdeki mesajlari gorur.
        Diger processleri izlemek icin DLL injection gerekir (Win32 sinirlari).
        Yine de shell/pencere degisikliklerini yakalamak icin faydali."""
        WH_CALLWNDPROCRET = 12
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        HOOKPROC = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_int, ctypes.c_ulonglong, ctypes.c_longlong)

        self._hook_ref = None
        emit = self.emit

        def _proc(nCode, wParam, lParam):
            if nCode >= 0 and wParam in (0x0006, 0x001C):  # WM_ACTIVATE, WM_ACTIVATEAPP
                try:
                    hwnd = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulonglong))[0]
                    class_buf = ctypes.create_unicode_buffer(256)
                    user32.GetClassNameW(hwnd, class_buf, 256)
                    title_buf = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(hwnd, title_buf, 512)
                    if class_buf.value or title_buf.value:
                        emit(UEvent('Win32','Hook',
                            f'Pencere aktivasyonu: class={class_buf.value} title={title_buf.value[:120]}',
                            level='info'))
                except Exception: pass
            return user32.CallNextHookEx(None, nCode, wParam, lParam)

        cb = HOOKPROC(_proc)
        self._hook_ref = cb  # referansi tut, GC olmasin
        h = user32.SetWindowsHookExW(WH_CALLWNDPROCRET, cb,
                                     kernel32.GetModuleHandleW(None), 0)
        if h:
            self.hooks.append(h)
            self.emit(UEvent('Win32','Hook','WH_CALLWNDPROCRET hook kuruldu', level='info'))
        else:
            err = ctypes.get_last_error()
            self.emit(UEvent('Win32','Hook', f'SetWindowsHookExW basarisiz: {err}', level='error'))

    def stop(self):
        self.running = False
        if HAVE_WIN32:
            for h in self.hooks:
                try: ctypes.windll.user32.UnhookWindowsHookEx(h)
                except Exception: pass


# =================================================================
#  6. ANA TRACER - Tum collector'lari yonetir
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

        # Eksik bagimliliklari uyar
        missing = []
        if not HAVE_PSUTIL: missing.append('psutil')
        if not HAVE_WMI: missing.append('wmi')
        if not HAVE_WIN32: missing.append('pywin32')
        if not HAVE_ETW: missing.append('pywintrace')
        if not HAVE_PROCMON_PARSER: missing.append('procmon-parser')
        if missing:
            self.emit(UEvent('System','Error',
                f'Eksik kutuphaneler: {", ".join(missing)}', level='error'))
        if not PROCMON_EXE:
            self.emit(UEvent('System','Error',
                'Procmon64.exe bulunamadi (ayni klasore koy).', level='error'))

        self.emit(UEvent('System','Process',
            f'=== BIRLESIK TRACE BASLADI === {self.start_time}', level='info'))

        # Tum collector'lari baslat
        collectors = []
        if PROCMON_EXE and HAVE_PROCMON_PARSER:
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
            self.emit(UEvent('System','Process',
                f'{c.__class__.__name__} baslatildi', level='info'))

        self.emit(UEvent('System','Process',
            f'Toplam {len(collectors)} collector aktif. '
            f'Simdi sorunu tekrar uret.', level='info'))

    def stop(self):
        if not self.running: return
        self.running = False
        self.emit(UEvent('System','Process','Trace durduruluyor...', level='info'))
        for c in self.collectors:
            try: c.stop()
            except Exception: pass
        for c in self.collectors:
            try:
                if c.is_alive():
                    c.join(timeout=3)
            except Exception: pass
        self.emit(UEvent('System','Process',
            f'=== TRACE BITTI === {datetime.now()} '
            f'(sure: {datetime.now() - self.start_time})', level='info'))


# =================================================================
#  GUI
# =================================================================
class App:
    SOURCES = {
        'ProcMon':  {'label':'ProcMon','color':'#ff9f43'},
        'ETW':      {'label':'ETW','color':'#54a0ff'},
        'WMI':      {'label':'WMI','color':'#5f27cd'},
        'psutil':   {'label':'psutil','color':'#10ac84'},
        'Win32':    {'label':'Win32','color':'#c8d6e5'},
        'EvtLog':   {'label':'EvtLog','color':'#ee5253'},
        'System':   {'label':'System','color':'#8395a7'},
    }
    ETYPES = {
        'Process':'#7ec8ff', 'Registry':'#f0c060', 'File':'#a4e400',
        'Network':'#ff9ff3', 'Hook':'#c8d6e5', 'Log':'#ff6b6b',
        'Error':'#ff6b6b', 'Unknown':'#dcdcdc',
    }

    def __init__(self, root):
        self.root = root
        root.title('Olay Yeri Inceleme v2 - Unified Trace Toolkit')
        root.geometry('1400x860')

        self.queue = queue.Queue()
        self.tracer = UnifiedTracer(self._emit_u)
        self.log = []  # (UEvent, formatted_line)

        # ---- Ust Bar ----
        top = ttk.Frame(root, padding=6); top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='\u25b6 Trace Baslat', command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='\u25a0 Durdur', command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f50d On Kontrol', command=self.precheck).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4be Log Kaydet (JSON)', command=self.save_json).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4be Log Kaydet (CSV)', command=self.save_csv).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f5d1 Temizle', command=self.clear).pack(side='left', padx=4)

        self.status = ttk.Label(top, text='Hazir', foreground='gray')
        self.status.pack(side='right')

        # ---- Durum cubugu (collector'lar) ----
        stat = ttk.Frame(root, padding=(6,0)); stat.pack(fill='x')
        self.collector_labels = {}
        for src, meta in self.SOURCES.items():
            if src == 'System': continue
            lbl = tk.Label(stat, text=f'\u25cf {meta["label"]}',
                          fg='gray', font=('Segoe UI', 8, 'bold'))
            lbl.pack(side='left', padx=4)
            self.collector_labels[src] = lbl

        # ---- Filtre Bar ----
        filt = ttk.LabelFrame(root, text='Filtre', padding=6)
        filt.pack(fill='x', padx=6, pady=(4,0))

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

        self.f_search = tk.StringVar()
        ent = ttk.Entry(filt, textvariable=self.f_search, width=22)
        ent.pack(side='left', padx=8)
        ent.bind('<KeyRelease>', lambda e: self.refilter())
        ttk.Label(filt, text='Ara:').pack(side='left')

        # ---- Log Alani ----
        wrap = ttk.Frame(root); wrap.pack(fill='both', expand=True, padx=6, pady=6)
        self.txt = scrolledtext.ScrolledText(
            wrap, wrap='none', font=('Consolas', 9),
            bg='#0d0d12', fg='#dcdcdc', insertbackground='white')
        self.txt.pack(fill='both', expand=True)
        # Renk tag'leri
        for src, meta in self.SOURCES.items():
            self.txt.tag_config(f'src_{src}', foreground=meta['color'])
        for et, col in self.ETYPES.items():
            self.txt.tag_config(f'type_{et}', foreground=col)
        self.txt.tag_config('error', foreground='#ff4757', font=('Consolas', 9, 'bold'))
        self.txt.tag_config('warn', foreground='#ffa502')
        self.txt.tag_config('change', foreground='#f0c060')
        self.txt.tag_config('info', foreground='#a4b0be')

        root.after(60, self._drain)

    # ---- Event emit ----
    def _emit_u(self, uevent):
        self.queue.put(uevent)

    def _drain(self):
        try:
            while True:
                ev = self.queue.get_nowait()
                self.log.append(ev)
                if self._passes(ev):
                    self._write_event(ev)
                # Collector durum isigi
                if ev.source in self.collector_labels:
                    self.collector_labels[ev.source].config(fg='green')
        except queue.Empty:
            pass
        self.root.after(60, self._drain)

    def _passes(self, ev):
        if not self.f_sources.get(ev.source, tk.BooleanVar(value=True)).get():
            return False
        if not self.f_types.get(ev.etype, tk.BooleanVar(value=True)).get():
            return False
        if self.f_err_only.get() and ev.level not in ('error','warn'):
            return False
        q = self.f_search.get().lower()
        if q and q not in ev.details.lower():
            return False
        return True

    def _write_event(self, ev):
        ts = ev.ts.strftime('%H:%M:%S.%f')[:-3]
        src = f'[{ev.source}]'
        et  = f'[{ev.etype}]'
        line = f'{ts} {src:<9} {et:<10} {ev.details}\n'
        tag = 'error' if ev.level == 'error' else \
              'warn' if ev.level == 'warn' else \
              'change' if ev.level == 'change' else 'info'
        # insert parcali (renklendirme icin)
        start = self.txt.index('end-1c')
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
        threading.Thread(target=self.tracer.start, daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.status.config(text='CALISIYOR', foreground='green')

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.status.config(text='DURDURULDU', foreground='orange')

    def precheck(self):
        threading.Thread(target=self._precheck_worker, daemon=True).start()

    def _precheck_worker(self):
        def e(d): self._emit_u(UEvent('System','Error', d, level='error'))
        def i(d): self._emit_u(UEvent('System','Process', d, level='info'))
        i('========== ON KONTROL v2 ==========')

        # ProcMon varlik
        if PROCMON_EXE: i(f'ProcMon: {PROCMON_EXE}')
        else: e('ProcMon: YOK (Procmon64.exe ayni klasore koy)')

        # Bagimliliklar
        for name, ok in (('psutil',HAVE_PSUTIL),('wmi',HAVE_WMI),
                         ('pywin32',HAVE_WIN32),('pywintrace',HAVE_ETW),
                         ('procmon-parser',HAVE_PROCMON_PARSER)):
            if ok: i(f'{name}: OK')
            else: e(f'{name}: YOK -> pip install {name}')

        # Policy keys (duvar kagidi)
        pol = [
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingLockScreen'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'LockScreenImagePath'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP', 'DesktopImagePath'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Explorer', 'NoSaveSettings'),
        ]
        i('[Policy Kontrolu]')
        hive_map = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE}
        found = False
        for hive, path, name in pol:
            try:
                k = winreg.OpenKey(hive_map[hive], path)
                v, _ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                e(f'  >> POLITIKA: {hive}\\{path}\\{name} = {v}')
                found = True
            except FileNotFoundError: pass
            except OSError: pass
        if not found: i('  Politika key bulunamadi (iyi haber)')

        # Servisler
        i('[Servisler]')
        if HAVE_PSUTIL:
            for svc in ('Themes','AppXSvc','ClipSVC','StateRepository',
                        'TokenBroker','Dwm','UxSms','ShellHWDetection'):
                try:
                    s = psutil.win_service_get(svc); d = s.as_dict()
                    if d.get('status') != 'running' or d.get('start_type') == 'disabled':
                        e(f'  >> SORUNLU: {svc} status={d.get("status")} start={d.get("start_type")}')
                    else: i(f'  OK: {svc}')
                except Exception as ex:
                    e(f'  >> Servis yok: {svc} ({ex})')

        # TranscodedWallpaper yazilabilirlik
        i('[Wallpaper Dosya]')
        ad = os.environ.get('APPDATA','')
        wp = os.path.join(ad,'Microsoft','Windows','Themes','TranscodedWallpaper')
        if os.path.exists(wp):
            try:
                with open(wp,'ab'): pass
                i(f'  OK yazilabilir: {wp}')
            except Exception as ex:
                e(f'  >> YAZILAMAZ: {wp} -> {ex}')
        else:
            i(f'  Dosya yok (normal): {wp}')

        # PersonalizationCSP
        i('[PersonalizationCSP]')
        try:
            k = winreg.OpenKey(hive_map['HKLM'],
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP')
            for vn in ('LockScreenImagePath','DesktopImagePath',
                       'LockScreenImageUrl','DesktopImageUrl'):
                try:
                    v, _ = winreg.QueryValueEx(k, vn)
                    e(f'  >> CSP: {vn} = {v}')
                except FileNotFoundError: pass
            winreg.CloseKey(k)
        except FileNotFoundError:
            i('  PersonalizationCSP yok (normal)')

        i('========== ON KONTROL BITTI ==========')

    def save_json(self):
        p = filedialog.asksaveasfilename(defaultextension='.json',
                                         filetypes=[('JSON','*.json')])
        if not p: return
        data = []
        for ev in self.log:
            data.append({
                'ts': ev.ts.isoformat(),
                'source': ev.source, 'type': ev.etype,
                'pid': ev.pid, 'level': ev.level, 'details': ev.details,
            })
        with open(p,'w',encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        messagebox.showinfo('Kaydedildi', f'{len(data)} event -> {p}')

    def save_csv(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv',
                                         filetypes=[('CSV','*.csv')])
        if not p: return
        with open(p,'w',encoding='utf-8',newline='') as f:
            w = csv.writer(f)
            w.writerow(['timestamp','source','type','pid','level','details'])
            for ev in self.log:
                w.writerow([ev.ts.isoformat(), ev.source, ev.etype,
                            ev.pid or '', ev.level, ev.details])
        messagebox.showinfo('Kaydedildi', f'{len(self.log)} event -> {p}')

    def clear(self):
        self.log.clear()
        self.txt.delete('1.0','end')


def main():
    root = tk.Tk()
    try: root.call('tk','scaling',1.1)
    except Exception: pass
    App(root)
    root.mainloop()

if __name__ == '__main__':
    main()