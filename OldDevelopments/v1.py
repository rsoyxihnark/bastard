
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, sys, subprocess, queue, winreg, re
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    r = tk.Tk(); r.withdraw()
    messagebox.showerror("Eksik", "psutil yok. Kur: pip install psutil")
    sys.exit(1)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False

HIVES = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE}

WATCH_REG_KEYS = [
    ('HKCU', r'Control Panel\Desktop'),
    ('HKCU', r'Control Panel\Desktop\WindowMetrics'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Lock Screen'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Themes'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies'),
    ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization'),
    ('HKCU', r'Software\Classes\ActivatableClasses\Package'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background'),
    ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization'),
    ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\System'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
]

NO_WINDOW = 0x08000000


def default_watch_folders():
    la = os.environ.get('LOCALAPPDATA', '')
    ad = os.environ.get('APPDATA', '')
    cands = [
        os.path.join(la, 'Packages', 'Microsoft.Windows.Photos_8wekyb3d8bbwe'),
        os.path.join(la, 'Microsoft', 'Windows', 'Themes'),
        os.path.join(ad, 'Microsoft', 'Windows', 'Themes'),
        os.path.join(la, 'Microsoft', 'Windows', 'Explorer'),
    ]
    return [f for f in cands if os.path.exists(f)]


class Tracer:
    def __init__(self, emit):
        self.emit = emit
        self.running = False
        self.start_time = None
        self.start_time_utc = None
        self.reg_snapshot = {}
        self.proc_seen = set()
        self.observer = None
        self.watch_folders = []
        self.error_count = 0

    def start(self, folders):
        if self.running:
            return
        self.running = True
        self.start_time = datetime.now()
        self.start_time_utc = datetime.utcnow()
        self.error_count = 0
        self.watch_folders = [f for f in folders if os.path.exists(f)]

        self.emit('INFO', f'Trace basladi: {self.start_time}', 'info')
        self.emit('INFO', f'Izlenen klasorler ({len(self.watch_folders)}):', 'info')
        for f in self.watch_folders:
            self.emit('INFO', f'   {f}', 'info')

        self.reg_snapshot = self._read_registry_all()
        self.emit('INFO', f'Registry snapshot: {len(self.reg_snapshot)} deger', 'info')

        self.proc_seen = {p.pid for p in psutil.process_iter(['pid'])}
        self.emit('INFO', f'Aktif process: {len(self.proc_seen)}', 'info')

        for name in ('Photos.exe', 'RuntimeBroker.exe', 'dllhost.exe',
                     'ShellExperienceHost.exe', 'explorer.exe'):
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    if p.info['name'] and p.info['name'].lower() == name.lower():
                        self.emit('PROC?', f'Mevcut: {name} PID={p.info["pid"]}', 'proc')
                except Exception:
                    pass

        for tgt in (self._watch_processes, self._watch_registry):
            t = threading.Thread(target=tgt, daemon=True)
            t.start()

        if HAVE_WATCHDOG and self.watch_folders:
            self._start_file_watcher()

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.emit('INFO', 'Trace durduruluyor...', 'info')
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.observer = None
        try:
            final = self._read_registry_all()
            self._diff_registry(self.reg_snapshot, final)
        except Exception as e:
            self.emit('ERR', f'Son registry diff hatasi: {e}', 'error')
        self._scan_event_log()
        self.emit('INFO', f'Trace bitti: {datetime.now()} | Toplam hata: {self.error_count}', 'info')

    def _read_registry_all(self):
        out = {}
        for hive_name, base in WATCH_REG_KEYS:
            self._walk(HIVES[hive_name], hive_name, base, out, 0, 6)
        return out

    def _walk(self, hive, hive_name, path, out, depth, max_depth):
        if depth > max_depth:
            return
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            return
        try:
            i = 0
            while True:
                try:
                    name, val, typ = winreg.EnumValue(key, i)
                    full = f'{hive_name}\\{path}\\{name}'
                    try:
                        val_s = str(val)
                    except Exception:
                        val_s = repr(val)
                    out[full] = (typ, val_s)
                    i += 1
                except OSError:
                    break
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    self._walk(hive, hive_name, path + '\\' + sub, out, depth + 1, max_depth)
                    i += 1
                except OSError:
                    break
        finally:
            try:
                winreg.CloseKey(key)
            except Exception:
                pass

    def _watch_registry(self):
        while self.running:
            time.sleep(1.0)
            try:
                cur = self._read_registry_all()
            except Exception as e:
                self.emit('ERR', f'Registry okuma hatasi: {e}', 'error')
                continue
            self._diff_registry(self.reg_snapshot, cur)
            self.reg_snapshot = cur

    def _diff_registry(self, old, new):
        for k, v in new.items():
            if k not in old:
                self.emit('REG+', f'{k} = {v[1]}', 'change')
            elif old[k] != v:
                self.emit('REG~', f'{k}: {old[k][1]} -> {v[1]}', 'change')
        for k, v in old.items():
            if k not in new:
                self.emit('REG-', f'{k} silindi (eski: {v[1]})', 'change')

    def _watch_processes(self):
        while self.running:
            time.sleep(0.4)
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    if p.pid in self.proc_seen:
                        continue
                    self.proc_seen.add(p.pid)
                    try:
                        info = p.info
                        cmd = ' '.join(info.get('cmdline') or []) or info.get('exe') or ''
                        self.emit('PROC+', f'[{info.get("name")}] PID={p.pid}  {cmd}', 'proc')
                    except Exception:
                        pass
            except Exception:
                pass

    def _start_file_watcher(self):
        outer = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory:
                    return
                src = getattr(event, 'src_path', '')
                dest = getattr(event, 'dest_path', '')
                outer.emit('FILE', f'{event.event_type}: {src}{(" -> " + dest) if dest else ""}', 'file')

        self.observer = Observer()
        h = Handler()
        for f in self.watch_folders:
            try:
                self.observer.schedule(h, f, recursive=True)
            except Exception as e:
                self.emit('ERR', f'Klasor izlenemedi {f}: {e}', 'error')
        try:
            self.observer.start()
            self.emit('INFO', 'Dosya izleyici aktif (watchdog)', 'info')
        except Exception as e:
            self.emit('ERR', f'Watchdog baslatilamadi: {e}', 'error')

    def _scan_event_log(self):
        import xml.etree.ElementTree as ET
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        pat = re.compile(r'<Event\b.*?</Event>', re.DOTALL)
        start_naive = self.start_time_utc

        for channel in ('Application', 'System'):
            try:
                out = subprocess.check_output(
                    ['wevtutil', 'qe', channel, '/c:150', '/rd:true', '/f:xml'],
                    stderr=subprocess.DEVNULL, timeout=15,
                    creationflags=NO_WINDOW,
                ).decode('utf-8', errors='replace')
            except Exception as e:
                self.emit('ERR', f'Event log okunamadi ({channel}): {e}', 'error')
                continue

            for xmlstr in pat.findall(out):
                try:
                    root = ET.fromstring(xmlstr)
                except Exception:
                    continue
                sys_el = root.find('e:System', ns)
                if sys_el is None:
                    continue
                tc = sys_el.find('e:TimeCreated', ns)
                if tc is None:
                    continue
                t_raw = tc.attrib.get('SystemTime', '')
                try:
                    evt_dt = datetime.strptime(t_raw[:19], '%Y-%m-%dT%H:%M:%S')
                except Exception:
                    continue
                if evt_dt < start_naive:
                    continue
                lvl_el = sys_el.find('e:Level', ns)
                lvl = (lvl_el.text or '4') if lvl_el is not None else '4'
                if lvl not in ('1', '2', '3'):
                    continue
                prov_el = sys_el.find('e:Provider', ns)
                prov = prov_el.attrib.get('Name', '?') if prov_el is not None else '?'
                eid_el = sys_el.find('e:EventID', ns)
                eid = (eid_el.text or '?') if eid_el is not None else '?'
                lvl_map = {'1': 'CRIT', '2': 'ERR', '3': 'WARN'}
                self.error_count += 1
                self.emit('EVT', f'[{channel}] {lvl_map.get(lvl, lvl)} {prov} ID={eid} @ {t_raw}', 'error')
                ed = root.find('e:EventData', ns)
                if ed is not None:
                    parts = []
                    for d in ed.findall('e:Data', ns):
                        nm = d.attrib.get('Name', '')
                        vv = (d.text or '').strip()
                        parts.append(f'{nm}={vv}' if nm else vv)
                    if parts:
                        joined = ' | '.join(parts)
                        self.emit('EVT', '    ' + joined[:500], 'error')
                        low = joined.lower()
                        if ('access' in low and 'denied' in low) or \
                           ('erişim' in low and 'engellendi' in low) or \
                           '0x80070005' in low:
                            self.emit('EVT', '    >>> ERISIM ENGELLENDI IPUCU <<<', 'error')

    def run_precheck(self):
        self.emit('INFO', '========== ON KONTROL ==========', 'info')

        try:
            ps = ("Get-AppxPackage Microsoft.Windows.Photos | "
                  "Select-Object Name,Version,Status,InstallLocation | Format-List | Out-String")
            out = subprocess.check_output(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps],
                stderr=subprocess.STDOUT, timeout=20, creationflags=NO_WINDOW,
            ).decode('utf-8', errors='replace').strip()
            self.emit('INFO', '[Photos AppX]\n' + out, 'info')
        except Exception as e:
            self.emit('WARN', f'AppX sorgu hatasi: {e}', 'error')

        pol = [
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 'WallpaperStyle'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
            ('HKCU', r'Software\Policies\Microsoft\Windows\Personalization', 'NoChangingLockScreen'),
            ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'Wallpaper'),
            ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoChangingWallPaper'),
        ]
        self.emit('INFO', '[Policy Kontrolu]', 'info')
        found_policy = False
        for hive, path, name in pol:
            try:
                k = winreg.OpenKey(HIVES[hive], path)
                v, _ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                self.emit('WARN', f'  >> POLITIKA: {hive}\\{path}\\{name} = {v}', 'error')
                found_policy = True
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if not found_policy:
            self.emit('INFO', '  Politika key bulunamadi (iyi haber)', 'info')

        self.emit('INFO', '[Servis Kontrolu]', 'info')
        for svc in ('Themes', 'AppXSvc', 'ClipSVC', 'StateRepository', 'TokenBroker', 'Dwm', 'UxSms'):
            try:
                s = psutil.win_service_get(svc)
                d = s.as_dict()
                st = d.get('status', '?')
                start = d.get('start_type', '?')
                if st != 'running' or start == 'disabled':
                    self.emit('WARN', f'  >> SORUNLU: {svc} status={st} start={start}', 'error')
                else:
                    self.emit('INFO', f'  OK: {svc} ({st}/{start})', 'info')
            except Exception as e:
                self.emit('WARN', f'  >> Servis erisilemedi: {svc} ({e})', 'error')

        self.emit('INFO', '[Wallpaper Dosya Kontrolu]', 'info')
        ad = os.environ.get('APPDATA', '')
        wp = os.path.join(ad, 'Microsoft', 'Windows', 'Themes', 'TranscodedWallpaper')
        if os.path.exists(wp):
            try:
                with open(wp, 'ab'):
                    pass
                self.emit('INFO', f'  OK yazilabilir: {wp}', 'info')
            except Exception as e:
                self.emit('WARN', f'  >> YAZILAMAZ: {wp} -> {e}', 'error')
        else:
            self.emit('WARN', f'  Dosya yok: {wp}', 'error')

        self.emit('INFO', '[Registry ACL]', 'info')
        try:
            ps = r'(Get-Acl "HKCU:\Control Panel\Desktop").Access | Format-Table IdentityReference,RegistryRights,AccessControlType -AutoSize | Out-String'
            out = subprocess.check_output(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps],
                stderr=subprocess.STDOUT, timeout=15, creationflags=NO_WINDOW,
            ).decode('utf-8', errors='replace').strip()
            self.emit('INFO', out, 'info')
            if 'Deny' in out:
                self.emit('WARN', '  >> DENY kurali var! Wallpaper yazimini engelleyebilir.', 'error')
        except Exception as e:
            self.emit('WARN', f'ACL sorgu hatasi: {e}', 'error')

        self.emit('INFO', '========== ON KONTROL BITTI ==========', 'info')


class App:
    def __init__(self, root):
        self.root = root
        root.title('Olay Yeri Inceleme - TraceMon Lite')
        root.geometry('1200x760')

        self.queue = queue.Queue()
        self.tracer = Tracer(self._emit)
        self.log_lines = []

        top = ttk.Frame(root, padding=6)
        top.pack(fill='x')
        self.btn_start = ttk.Button(top, text='\u25b6 Trace Baslat', command=self.start)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(top, text='\u25a0 Durdur', command=self.stop, state='disabled')
        self.btn_stop.pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f50d On Kontrol', command=self.precheck).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f4be Log Kaydet', command=self.save).pack(side='left', padx=4)
        ttk.Button(top, text='\U0001f5d1 Temizle', command=self.clear).pack(side='left', padx=4)
        self.status = ttk.Label(top, text='Hazir', foreground='gray')
        self.status.pack(side='right')

        filt = ttk.Frame(root, padding=(6, 0))
        filt.pack(fill='x')
        self.f_proc = tk.BooleanVar(value=True)
        self.f_file = tk.BooleanVar(value=True)
        self.f_reg = tk.BooleanVar(value=True)
        self.f_evt = tk.BooleanVar(value=True)
        self.f_info = tk.BooleanVar(value=True)
        self.f_err_only = tk.BooleanVar(value=False)
        for label, var in (('Process', self.f_proc), ('File', self.f_file),
                           ('Registry', self.f_reg), ('EventLog', self.f_evt),
                           ('Info/Status', self.f_info)):
            ttk.Checkbutton(filt, text=label, variable=var, command=self.refilter).pack(side='left', padx=2)
        ttk.Checkbutton(filt, text='Sadece Hata', variable=self.f_err_only,
                        command=self.refilter).pack(side='left', padx=(20, 0))

        wrap_frame = ttk.Frame(root)
        wrap_frame.pack(fill='both', expand=True, padx=6, pady=6)
        self.txt = scrolledtext.ScrolledText(wrap_frame, wrap='none',
                                             font=('Consolas', 9),
                                             bg='#101014', fg='#dcdcdc',
                                             insertbackground='white')
        self.txt.pack(fill='both', expand=True)
        self.txt.tag_config('error', foreground='#ff6b6b')
        self.txt.tag_config('change', foreground='#f0c060')
        self.txt.tag_config('proc', foreground='#7ec8ff')
        self.txt.tag_config('file', foreground='#a4e400')
        self.txt.tag_config('info', foreground='#8a8a8a')

        root.after(80, self._drain)

        if not HAVE_WATCHDOG:
            self._emit('INFO', 'watchdog yok: dosya izleme devre disi. "pip install watchdog"', 'error')

    def _emit(self, kind, msg, level='info'):
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        line = f'[{ts}] [{kind}] {msg}'
        self.queue.put((line, level, kind))

    def _drain(self):
        try:
            while True:
                line, level, kind = self.queue.get_nowait()
                self.log_lines.append((line, level, kind))
                if self._passes_filter(kind, level):
                    self._write(line, level)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    def _passes_filter(self, kind, level):
        if self.f_err_only.get() and level != 'error':
            return False
        if kind.startswith('PROC') and not self.f_proc.get():
            return False
        if kind == 'FILE' and not self.f_file.get():
            return False
        if kind.startswith('REG') and not self.f_reg.get():
            return False
        if kind == 'EVT' and not self.f_evt.get():
            return False
        if kind in ('INFO', 'WARN', 'ERR') and not self.f_info.get():
            return False
        return True

    def _write(self, line, level):
        self.txt.insert('end', line + '\n', level)
        self.txt.see('end')

    def refilter(self):
        self.txt.delete('1.0', 'end')
        for line, level, kind in self.log_lines:
            if self._passes_filter(kind, level):
                self._write(line, level)

    def start(self):
        folders = default_watch_folders()
        threading.Thread(target=self.tracer.start, args=(folders,), daemon=True).start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.status.config(text='CALISIYOR', foreground='green')

    def stop(self):
        threading.Thread(target=self.tracer.stop, daemon=True).start()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.status.config(text='DURDURULDU', foreground='orange')

    def precheck(self):
        threading.Thread(target=self.tracer.run_precheck, daemon=True).start()

    def save(self):
        p = filedialog.asksaveasfilename(defaultextension='.log',
                                         filetypes=[('Log', '*.log'), ('Tumu', '*.*')])
        if not p:
            return
        with open(p, 'w', encoding='utf-8') as f:
            for line, _, _ in self.log_lines:
                f.write(line + '\n')
        messagebox.showinfo('Kaydedildi', p)

    def clear(self):
        self.log_lines.clear()
        self.txt.delete('1.0', 'end')


def main():
    root = tk.Tk()
    try:
        root.call('tk', 'scaling', 1.15)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == '__main__':
    main()