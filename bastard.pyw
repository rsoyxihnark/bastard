import bisect
import configparser
import csv
import ctypes
import ctypes.wintypes as wt
import json
import logging
import logging.handlers
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape

import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

VERSION = "1.3.0"

APP_NAME = "Bastard"
IS_WIN = os.name == "nt"

if IS_WIN:
    import winreg
else:
    winreg = None

try:
    import psutil
except Exception:
    psutil = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:
    FileSystemEventHandler = object
    Observer = None

etw_core = None
EtwGuid = None
if IS_WIN:
    try:
        import etw.etw as etw_core
        from etw.GUID import GUID as EtwGuid
    except Exception:
        etw_core = None
        EtwGuid = None

try:
    from procmon_parser import ProcmonLogsReader
    from procmon_parser.consts import get_error_message as procmon_result_text
except Exception:
    ProcmonLogsReader = None
    procmon_result_text = None

wmi_module = None
pythoncom = None
if IS_WIN:
    try:
        import wmi as wmi_module
        import pythoncom
    except Exception:
        wmi_module = None
        pythoncom = None

INFO = "info"
CHANGE = "change"
WARN = "warn"
ERROR = "error"
MARK = "marker"
LEVEL_LABELS = {INFO: "Info", CHANGE: "Change", WARN: "Warning", ERROR: "Problem", MARK: "Marker"}

SRC_SYSTEM = "System"
SRC_REG = "Registry"
SRC_FILES = "Files"
SRC_PROC = "Processes"
SRC_WIN = "Windows"
SRC_LOG = "Event Log"
SRC_PM = "ProcMon"
SRC_WALL = "Wallpaper"
SRC_ETW = "ETW"
SRC_WMI = "WMI"
SRC_PROBE = "Probes"
SRC_TRACE = "Trace Tools"

KIND_REG = "Registry"
KIND_FILE = "File"
KIND_PROC = "Process"
KIND_WIN = "Window"
KIND_DESK = "Desktop"
KIND_LOG = "Log"
KIND_SYS = "System"
KIND_MARK = "Marker"
KIND_PROBE = "Probe"
KIND_ETW = "Trace"
KIND_NET = "Network"

CREATE_NO_WINDOW = 0x08000000
FILETIME_EPOCH = 116444736000000000
MARKER_WINDOW = 6
MARKER_DELAY = 8.5
VIEW_LIMIT = 20000
STORE_LIMIT = 1000000
LOUD_SOURCES = frozenset((SRC_ETW, SRC_PM, SRC_TRACE))
FLOOD_SHARE = 0.8
SELFTEST_EVENTS = 50000
INTERNAL_ERRORS = []

FOLDERID_DESKTOP = "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"


def program_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def known_folder(guid_text):
    if not IS_WIN:
        return ""
    try:
        shell32 = ctypes.WinDLL("shell32")
        ole32 = ctypes.WinDLL("ole32")
        fn = shell32.SHGetKnownFolderPath
        fn.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        fn.restype = ctypes.c_long
        guid = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(guid_text).bytes_le)
        out = ctypes.c_void_p()
        if fn(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0 or not out.value:
            return ""
        try:
            return ctypes.wstring_at(out.value)
        finally:
            ole32.CoTaskMemFree(out)
    except Exception:
        return ""


def find_desktop():
    path = known_folder(FOLDERID_DESKTOP)
    if path and os.path.isdir(path):
        return path
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    for candidate in (os.path.join(home, "Desktop"), os.path.join(home, "OneDrive", "Desktop")):
        if os.path.isdir(candidate):
            return candidate
    return home


def find_data_dir():
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return os.path.join(base, APP_NAME)
    return os.path.join(os.path.expanduser("~"), "." + APP_NAME.lower())


def find_program_dir():
    try:
        if getattr(sys, "frozen", False):
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()


DESKTOP = find_desktop()
DATA_DIR = find_data_dir()
PROGRAM_DIR = find_program_dir()
TRACE_DIR = os.path.join(DATA_DIR, "Traces")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
EXCLUSIONS_PATH = os.path.join(PROGRAM_DIR, "Exclusions.ini")
APP_LOG_PATH = os.path.join(DATA_DIR, "Bastard.log")
LOG = logging.getLogger("bastard")


def setup_app_log():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(APP_LOG_PATH, maxBytes=1000000, backupCount=1, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(message)s"))
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    except Exception:
        pass
    for name in ("etw", "watchdog", "procmon_parser"):
        logging.getLogger(name).setLevel(logging.ERROR)


def record_internal_error(text):
    INTERNAL_ERRORS.append(text)
    LOG.error("Internal error: %s", text)


def install_error_hooks():
    def on_error(kind, value, tb):
        record_internal_error("".join(traceback.format_exception(kind, value, tb)))

    def on_thread_error(args):
        record_internal_error("".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))

    sys.excepthook = on_error
    threading.excepthook = on_thread_error


def load_settings():
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
        LOG.warning("Settings file is not a JSON object, so the defaults are used")
    except FileNotFoundError:
        pass
    except Exception as exc:
        LOG.warning("Settings file could not be read, so the defaults are used: %s", exc)
    return {}


def save_settings(data):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        temp = SETTINGS_PATH + ".tmp"
        with open(temp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(temp, SETTINGS_PATH)
    except Exception as exc:
        LOG.warning("Settings could not be saved: %s", exc)


def is_admin():
    if not IS_WIN:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    try:
        exe = sys.executable
        if getattr(sys, "frozen", False):
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            quiet = os.path.join(os.path.dirname(exe), "pythonw.exe")
            if os.path.isfile(quiet):
                exe = quiet
            params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
        fn = ctypes.windll.shell32.ShellExecuteW
        fn.restype = ctypes.c_ssize_t
        return fn(None, "runas", exe, params or None, None, 1) > 32
    except Exception as exc:
        LOG.warning("Restart as administrator failed: %s", exc)
        return False


def enable_dpi_awareness():
    if not IS_WIN:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def run_hidden(cmd, timeout):
    options = {}
    if IS_WIN:
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = 0
        options["startupinfo"] = info
        options["creationflags"] = CREATE_NO_WINDOW
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


EARLIEST_TIME = 946684800.0


def sane_time(ts):
    now = time.time()
    if ts is None:
        return now, True
    try:
        value = float(ts)
    except (TypeError, ValueError):
        return now, False
    if value != value or value < EARLIEST_TIME or value > now + 86400.0:
        return now, False
    return value, True


def clock(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    except (OSError, OverflowError, ValueError, TypeError):
        return "??:??:??.???"


def stamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (OSError, OverflowError, ValueError, TypeError):
        return "????-??-?? ??:??:??.???"


def filetime_to_epoch(value):
    return (int(value) - FILETIME_EPOCH) / 10000000.0


SYSTEM_TIME_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")


def parse_system_time(text):
    match = SYSTEM_TIME_RE.match(text or "")
    if not match:
        return None
    parts = [int(match.group(i)) for i in range(1, 7)]
    base = datetime(*parts, tzinfo=timezone.utc).timestamp()
    fraction = match.group(7) or ""
    if fraction:
        base += int(fraction) / float(10 ** len(fraction))
    return base


def clean_text(value):
    text = "" if value is None else str(value)
    if "\x00" in text:
        text = text.replace("\x00", "")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
    return text


def shorten(value, limit):
    text = str(value).replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def one_line(value, limit=300):
    return shorten(" ".join(str(value).split()), limit)


def as_int(value, default=None):
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return default


def plural(count, word):
    return "%d %s" % (count, word if count == 1 else word + "s")


def duration_text(seconds):
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return plural(seconds, "second")
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return "%d min %d s" % (minutes, rest)
    hours, minutes = divmod(minutes, 60)
    return "%d h %d min" % (hours, minutes)


def short_duration(seconds):
    if seconds < 60:
        return "%.1f s" % max(0.0, seconds)
    return duration_text(seconds)


def exit_code_text(code):
    if code is None:
        return "unknown"
    code &= 0xFFFFFFFF
    if code >= 0x10000:
        return "0x%08X" % code
    return str(code)


REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}


def decode_transcoded_image(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) < 26:
        return ""
    text = bytes(data[24:]).decode("utf-16-le", "ignore").split("\x00", 1)[0].strip()
    if text and all(ch.isprintable() for ch in text):
        return text
    return ""


def format_reg_value(name, kind, data, limit=160):
    if data is None:
        return "(empty)"
    if kind in (1, 2, 6):
        return '"%s"' % shorten(data, limit)
    if kind in (4, 11) and isinstance(data, int):
        return "%d (0x%X)" % (data, data)
    if kind == 7 and isinstance(data, (list, tuple)):
        return "[%s]" % shorten(", ".join('"%s"' % item for item in data), limit)
    if isinstance(data, (bytes, bytearray)):
        if (name or "").lower() == "transcodedimagecache":
            path = decode_transcoded_image(data)
            if path:
                return 'image "%s" (%d bytes)' % (shorten(path, limit), len(data))
        if not data:
            return "0 bytes"
        head = bytes(data[:16]).hex(" ").upper()
        more = " ..." if len(data) > 16 else ""
        return "%d bytes: %s%s" % (len(data), head, more)
    return shorten(data, limit)


def full_reg_value(name, kind, data):
    return "%s %s" % (REG_TYPES.get(kind, "type %s" % kind), format_reg_value(name, kind, data, 4000))


def nice_reg_path(path, user_sid):
    low = path.lower()
    if low.startswith("\\registry\\machine"):
        return "HKLM" + path[17:]
    if low.startswith("\\registry\\user\\"):
        rest = path[15:]
        sid = (user_sid or "").lower()
        if sid and rest.lower().startswith(sid + "_classes"):
            return "HKCU\\Software\\Classes" + rest[len(sid) + 8:]
        if sid and rest.lower().startswith(sid):
            return "HKCU" + rest[len(sid):]
        return "HKU\\" + rest
    return path


def current_user_sid():
    if not IS_WIN:
        return ""
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wt.HANDLE
        kernel.CloseHandle.argtypes = [wt.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
                                               ctypes.POINTER(wt.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        token = wt.HANDLE()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return ""
        try:
            size = wt.DWORD(0)
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value:
                return ""
            buf = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, ctypes.addressof(buf), size.value, ctypes.byref(size)):
                return ""
            sid = ctypes.c_void_p.from_buffer(buf).value
            text = ctypes.c_void_p()
            if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                return ""
            try:
                return ctypes.wstring_at(text.value)
            finally:
                kernel.LocalFree(text)
        finally:
            kernel.CloseHandle(token)
    except Exception:
        return ""


class DeviceMap:
    def __init__(self):
        self.devices = []
        if not IS_WIN:
            return
        try:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel.QueryDosDeviceW
            query.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
            query.restype = wt.DWORD
            buf = ctypes.create_unicode_buffer(2048)
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if query(letter + ":", buf, 2048):
                    self.devices.append((buf.value.lower(), letter + ":"))
        except Exception:
            pass

    def to_dos(self, path):
        if not path:
            return path
        low = path.lower()
        if low.startswith("\\??\\"):
            return path[4:]
        if low.startswith("\\systemroot\\"):
            return os.environ.get("SystemRoot", "C:\\Windows") + path[11:]
        for device, letter in self.devices:
            if low.startswith(device + "\\"):
                return letter + path[len(device):]
        return path


class ProcessNames:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache = {}

    def put(self, pid, name):
        if pid and name:
            with self.lock:
                self.cache[pid] = (name, time.time())

    def get(self, pid):
        if not pid:
            return ""
        now = time.time()
        with self.lock:
            hit = self.cache.get(pid)
        if hit is not None and now - hit[1] < 30:
            return hit[0]
        name = hit[0] if hit is not None else ""
        if psutil is not None:
            try:
                name = psutil.Process(pid).name()
            except Exception:
                pass
        with self.lock:
            if len(self.cache) > 20000:
                self.cache.clear()
            self.cache[pid] = (name, now)
        return name


PROCESS_NAMES = ProcessNames()


class Event:
    __slots__ = ("ts", "seq", "source", "kind", "level", "pid", "proc", "text", "detail")

    def __init__(self, ts, seq, source, kind, level, pid, proc, text, detail):
        self.ts = ts
        self.seq = seq
        self.source = source
        self.kind = kind
        self.level = level
        self.pid = pid
        self.proc = proc
        self.text = text
        self.detail = detail

    def key(self):
        return (self.ts, self.seq)

    def who(self):
        if self.proc and self.pid:
            return "%s (PID %d)" % (self.proc, self.pid)
        if self.proc:
            return self.proc
        if self.pid:
            return "PID %d" % self.pid
        return ""

    def describe(self):
        lines = [
            "Time:     " + stamp(self.ts),
            "Source:   " + self.source,
            "Kind:     " + self.kind,
            "Level:    " + LEVEL_LABELS.get(self.level, self.level),
        ]
        who = self.who()
        if who:
            lines.append("Process:  " + who)
        lines.append("")
        lines.append(self.text)
        if self.detail:
            lines.append("")
            lines.append(self.detail)
        return "\n".join(lines)

    def to_dict(self):
        return {
            "time": stamp(self.ts), "epoch": round(self.ts, 6), "source": self.source, "kind": self.kind,
            "level": LEVEL_LABELS.get(self.level, self.level), "process": self.proc, "pid": self.pid,
            "event": self.text, "detail": self.detail,
        }

    def log_lines(self):
        head = "%s  %-10s %-8s %-8s %-30s %s" % (stamp(self.ts), self.source, self.kind,
                                                LEVEL_LABELS.get(self.level, self.level),
                                                shorten(self.who(), 30), self.text)
        lines = [head]
        for index, line in enumerate(self.detail.splitlines()):
            if index >= 40:
                lines.append("    ...")
                break
            lines.append("    " + line)
        return lines


def marker_summary(number, start, events):
    end = start + MARKER_WINDOW
    found = [ev for ev in events if start < ev.ts <= end and ev.source != SRC_SYSTEM]
    if not found:
        text = "Marker %d: nothing happened in the %d seconds after it" % (number, MARKER_WINDOW)
        return text, WARN, ""
    by_source = {}
    by_process = {}
    for ev in found:
        by_source[ev.source] = by_source.get(ev.source, 0) + 1
        if ev.proc:
            by_process[ev.proc] = by_process.get(ev.proc, 0) + 1
    parts = ", ".join("%s %d" % item for item in sorted(by_source.items(), key=lambda item: (-item[1], item[0])))
    text = "Marker %d: %s in the %d seconds after it (%s)" % (number, plural(len(found), "event"),
                                                          MARKER_WINDOW, parts)
    names = [name for name, _ in sorted(by_process.items(), key=lambda item: (-item[1], item[0]))[:4]]
    if names:
        text += ", from " + ", ".join(names)
    detail = "\n".join("%s  %-10s %s" % (clock(ev.ts), ev.source, one_line(ev.text, 160)) for ev in found[:60])
    return text, MARK, detail


class Hub:
    def __init__(self, exclusions=None):
        self.exclusions = exclusions
        self.lock = threading.Lock()
        self.seq = 0
        self.ui = queue.SimpleQueue()
        self.writer = None
        self.status = {}
        self.counts = {}
        self.bad_times = set()

    def emit(self, source, kind, text, level=INFO, pid=None, proc="", detail="", ts=None):
        text = clean_text(text)
        rules = self.exclusions
        if rules is not None and rules.blocks(source, level, text):
            return None
        original = ts
        ts, fine = sane_time(ts)
        if not fine and source not in self.bad_times:
            self.bad_times.add(source)
            LOG.warning("%s gave an event time that cannot be right (%r), so the time it arrived is used: %s",
                        source, original, one_line(text, 120))
        proc = clean_text(proc)
        detail = clean_text(detail)
        with self.lock:
            self.seq += 1
            ev = Event(ts, self.seq, source, kind, level, pid or None, proc, text, detail)
            self.counts[source] = self.counts.get(source, 0) + 1
            writer = self.writer
        if writer is not None:
            writer.put(ev)
        self.ui.put(ev)
        return ev

    def set_status(self, source, state, note=""):
        with self.lock:
            if self.status.get(source) == (state, note):
                return
            self.status[source] = (state, note)
        LOG.info("%s: %s %s", source, state, note)

    def snapshot(self):
        with self.lock:
            return dict(self.status), dict(self.counts)

    def reset(self, sources):
        with self.lock:
            self.counts = {}
            for source in sources:
                self.status[source] = ("idle", "")


class LogWriter:
    def __init__(self, path, header, max_bytes=0):
        self.path = path
        self.header = list(header)
        self.queue = queue.SimpleQueue()
        self.events = []
        self.error = ""
        self.handle = None
        self.thread = None
        self.max_bytes = max_bytes
        self.written = 0
        self.dropped = 0
        self.capped = False

    def start(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self.handle = open(self.path, "w", encoding="utf-8", errors="replace")
            self.handle.write("\n".join(self.header) + "\n\n")
            self.handle.flush()
        except Exception as exc:
            self.error = str(exc)
            self.handle = None
        self.thread = threading.Thread(target=self._run, name="log writer", daemon=True)
        self.thread.start()
        return self.handle is not None

    def put(self, ev):
        self.queue.put(ev)

    def _run(self):
        done = False
        while not done:
            batch = [self.queue.get()]
            try:
                while len(batch) < 5000:
                    batch.append(self.queue.get_nowait())
            except queue.Empty:
                pass
            lines = []
            for ev in batch:
                if ev is None:
                    done = True
                    continue
                if self.max_bytes and self.written >= self.max_bytes:
                    self.dropped += 1
                    continue
                rows = ev.log_lines()
                self.written += sum(len(row) + 1 for row in rows)
                self.events.append(ev)
                lines.extend(rows)
            if self.max_bytes and self.written >= self.max_bytes and not self.capped:
                self.capped = True
                lines.append("(the log stops here: it reached its %d MB limit)" % (self.max_bytes // (1024 * 1024)))
            if self.handle is not None and lines:
                try:
                    self.handle.write("\n".join(lines) + "\n")
                    self.handle.flush()
                except Exception as exc:
                    self.error = str(exc)

    def close(self, footer, rewrite):
        self.queue.put(None)
        footer = list(footer)
        if self.thread is not None:
            self.thread.join(timeout=20)
        if self.handle is not None:
            try:
                self.handle.close()
            except Exception:
                pass
            self.handle = None
        if self.dropped:
            footer.append("%s left out: the log reached its %d MB limit"
                          % (plural(self.dropped, "later event"), self.max_bytes // (1024 * 1024)))
        try:
            if rewrite:
                temp = self.path + ".tmp"
                with open(temp, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write("\n".join(self.header) + "\n\n")
                    for ev in sorted(self.events, key=Event.key):
                        fh.write("\n".join(ev.log_lines()) + "\n")
                    fh.write("\n" + "\n".join(footer) + "\n")
                os.replace(temp, self.path)
            else:
                with open(self.path, "a", encoding="utf-8", errors="replace") as fh:
                    fh.write("\n" + "\n".join(footer) + "\n")
            return True
        except Exception as exc:
            self.error = str(exc)
            LOG.warning("Trace log could not be finished: %s", exc)
            return False


class Store:
    def __init__(self, limit=STORE_LIMIT, flood_share=FLOOD_SHARE):
        self.limit = limit
        self.flood_limit = max(1, int(limit * flood_share))
        self.items = []
        self.by_seq = {}
        self.dropped = 0
        self.floods = 0
        self.unsorted = False

    def clear(self):
        self.items = []
        self.by_seq = {}
        self.dropped = 0
        self.floods = 0
        self.unsorted = False

    def add(self, events):
        ordered = True
        items = self.items
        for ev in events:
            flood = ev.level == INFO and ev.source in LOUD_SOURCES
            if len(items) >= self.limit or (flood and self.floods >= self.flood_limit):
                self.dropped += 1
                continue
            if items and ev.key() < items[-1].key():
                ordered = False
            items.append(ev)
            self.by_seq[ev.seq] = ev
            if flood:
                self.floods += 1
        if not ordered:
            self.unsorted = True
        return ordered

    def events(self):
        if self.unsorted:
            self.items.sort(key=Event.key)
            self.unsorted = False
        return self.items

    def window(self, start, end):
        items = self.events()
        low = bisect.bisect_right(items, start, key=lambda ev: ev.ts)
        high = bisect.bisect_right(items, end, key=lambda ev: ev.ts)
        return items[low:high]


DEFAULT_LOG_MB = 30
EXCLUSION_PARTS = 4
DEFAULT_EXCLUSIONS = (
    "ETW | info | [Kernel-File] | FileName=",
    "Trace Tools | info",
    "ProcMon | info",
)
EXCLUSION_HELP = (
    "One rule per line: source | level | the text it holds | the text that keeps it",
    "An empty part matches anything. The fourth part rescues an event the third one caught.",
    "Sources: Registry Files Processes Windows Event Log ProcMon Wallpaper ETW WMI Probes Trace Tools",
    "Levels: info change warn error marker. System events are never left out.",
)


def parse_exclusion(line):
    line = (line or "").strip()
    if not line or line[0] in "#;":
        return None
    parts = [part.strip().lower() for part in line.split("|")]
    while len(parts) < EXCLUSION_PARTS:
        parts.append("")
    return tuple(parts[:EXCLUSION_PARTS])


class Exclusions:
    def __init__(self, lines=(), log_mb=DEFAULT_LOG_MB, enabled=True):
        self.log_mb = log_mb
        self.enabled = enabled
        self.blocked = 0
        self.lines = []
        self.rules = []
        self.set_lines(lines)

    def set_lines(self, lines):
        self.lines = [line.strip() for line in lines if line.strip()]
        self.rules = [rule for rule in (parse_exclusion(line) for line in self.lines) if rule]

    def blocks(self, source, level, text):
        if not self.enabled or source == SRC_SYSTEM or not self.rules:
            return False
        low = (text or "").lower()
        name = (source or "").lower()
        mark = (level or "").lower()
        for want_source, want_level, holds, keeps in self.rules:
            if want_source and want_source != name:
                continue
            if want_level and want_level != mark:
                continue
            if holds and holds not in low:
                continue
            if keeps and keeps in low:
                continue
            self.blocked += 1
            return True
        return False

    def log_bytes(self):
        return max(1, self.log_mb) * 1024 * 1024


def load_exclusions(path=EXCLUSIONS_PATH):
    lines = list(DEFAULT_EXCLUSIONS)
    log_mb = DEFAULT_LOG_MB
    enabled = True
    parser = configparser.ConfigParser(interpolation=None)
    try:
        if parser.read(path, encoding="utf-8"):
            found = [row.strip() for row in parser.get("Exclusions", "rules", fallback="").splitlines()]
            found = [row for row in found if row]
            if found:
                lines = found
            enabled = parser.getboolean("Exclusions", "enabled", fallback=True)
            log_mb = parser.getint("Options", "max_log_mb", fallback=DEFAULT_LOG_MB)
    except (configparser.Error, OSError, ValueError) as exc:
        LOG.warning("Exclusions could not be read from %s: %s", path, exc)
    return Exclusions(lines, max(1, min(log_mb, 4096)), enabled)


def save_exclusions(rules, path=EXCLUSIONS_PATH):
    body = []
    for note in EXCLUSION_HELP:
        body.append("; " + note)
    body.append("")
    body.append("[Exclusions]")
    body.append("enabled = %s" % ("yes" if rules.enabled else "no"))
    body.append("rules =")
    for line in rules.lines:
        body.append("    " + line)
    body.append("")
    body.append("[Options]")
    body.append("max_log_mb = %d" % rules.log_mb)
    body.append("")
    try:
        temp = path + ".tmp"
        with open(temp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(body))
        os.replace(temp, path)
        return ""
    except OSError as exc:
        LOG.warning("Exclusions could not be written to %s: %s", path, exc)
        return str(exc)


def exclusion_from(ev):
    text = ev.text or ""
    match = re.search(r"0x[0-9A-Fa-f]+|\d{3,}", text)
    body = text[:match.start()] if match else text
    body = body.rstrip(" =|:,;-\t")
    if not body:
        body = text[:60]
    return "%s | %s | %s" % (ev.source, ev.level, body[:160])


def sample_events(events, limit):
    picked = [ev for ev in events if ev.source not in LOUD_SOURCES][:limit]
    share = max(0, limit - len(picked)) // (2 * len(LOUD_SOURCES))
    taken = {}
    for ev in events:
        if ev.source not in LOUD_SOURCES:
            continue
        slot = (ev.source, ev.level == INFO)
        seen = taken.get(slot, 0)
        if seen >= share:
            continue
        taken[slot] = seen + 1
        picked.append(ev)
    picked.sort(key=Event.key)
    return picked


class Source:
    name = ""

    def __init__(self, session):
        self.session = session
        self.hub = session.hub
        self.threads = []

    def emit(self, kind, text, level=INFO, pid=None, proc="", detail="", ts=None):
        return self.hub.emit(self.name, kind, text, level, pid, proc, detail, ts)

    def note(self, text, level=INFO, detail=""):
        return self.hub.emit(SRC_SYSTEM, KIND_SYS, "%s: %s" % (self.name, text), level, detail=detail)

    def status(self, state, note=""):
        self.hub.set_status(self.name, state, note)

    def stopping(self):
        return self.session.stop_event.is_set()

    def wait(self, seconds):
        return self.session.stop_event.wait(seconds)

    def spawn(self, target, label):
        thread = threading.Thread(target=self._guard, args=(target,), name="%s %s" % (self.name, label), daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread

    def _guard(self, target):
        try:
            target()
        except Exception as exc:
            record_internal_error(traceback.format_exc())
            self.status("failed", one_line(exc, 60))
            self.note("stopped working: %s" % one_line(exc, 200), ERROR, traceback.format_exc())

    def start(self):
        pass

    def stop(self):
        pass

    def join(self, timeout):
        end = time.time() + timeout
        for thread in self.threads:
            thread.join(max(0.0, end - time.time()))

    def finish(self):
        pass


REG_ROOTS = (
    ("HKCU", "Control Panel\\Desktop"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Lock Screen"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Themes"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Accent"),
    ("HKCU", "Software\\Microsoft\\Windows\\DWM"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\Background"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ActivatableClasses\\Package"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"),
    ("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
)
REG_NOTIFY_FILTER = 0x00000001 | 0x00000004
WAIT_TIMEOUT = 0x102
HIVE_ALIASES = {"HKEY_CURRENT_USER": "HKCU", "HKEY_LOCAL_MACHINE": "HKLM", "HKEY_USERS": "HKU",
                "HKEY_CLASSES_ROOT": "HKCR"}


def hive_handle(name):
    if winreg is None:
        return None
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKU": winreg.HKEY_USERS,
            "HKCR": winreg.HKEY_CLASSES_ROOT}.get(name.upper())


def split_reg_path(text):
    head, _, rest = text.strip().partition("\\")
    head = HIVE_ALIASES.get(head.upper(), head.upper())
    return head, rest.strip("\\")


def read_reg_tree(hive, path, max_depth=6, max_values=5000):
    keys = set()
    values = {}

    def walk(sub, depth):
        full = path + "\\" + sub if sub else path
        try:
            handle = winreg.OpenKey(hive, full, 0, winreg.KEY_READ)
        except OSError:
            if not sub:
                raise
            return
        children = []
        with handle:
            keys.add(sub)
            index = 0
            while len(values) < max_values:
                try:
                    name, data, kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                values[(sub, name)] = (kind, data)
                index += 1
            if depth < max_depth:
                index = 0
                while True:
                    try:
                        children.append(winreg.EnumKey(handle, index))
                    except OSError:
                        break
                    index += 1
        for child in children:
            walk(sub + "\\" + child if sub else child, depth + 1)

    walk("", 0)
    return keys, values


def _topmost(paths):
    chosen = []
    for path in sorted(paths, key=lambda p: (p.count("\\"), p.lower())):
        if any(path.lower().startswith(top.lower() + "\\") for top in chosen if top):
            continue
        chosen.append(path)
    return sorted(chosen, key=str.lower)


def reg_diff(old, new):
    old_keys, old_values = old
    new_keys, new_values = new
    added = _topmost(new_keys - old_keys)
    removed = _topmost(old_keys - new_keys)
    gone = [sub.lower() for sub in old_keys - new_keys]
    order = lambda ident: (ident[0].lower(), ident[1].lower())
    out = [("key added", sub, None, None, None) for sub in added]
    for ident in sorted(new_values, key=order):
        if ident not in old_values:
            out.append(("value added", ident[0], ident[1], None, new_values[ident]))
        elif old_values[ident] != new_values[ident]:
            out.append(("value changed", ident[0], ident[1], old_values[ident], new_values[ident]))
    for ident in sorted(old_values, key=order):
        if ident in new_values or ident[0].lower() in gone:
            continue
        out.append(("value deleted", ident[0], ident[1], old_values[ident], None))
    out.extend(("key deleted", sub, None, None, None) for sub in removed)
    return out


class _RegApi:
    def __init__(self):
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi.RegNotifyChangeKeyValue.argtypes = [ctypes.c_void_p, wt.BOOL, wt.DWORD, wt.HANDLE, wt.BOOL]
        self.advapi.RegNotifyChangeKeyValue.restype = wt.LONG
        self.kernel.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
        self.kernel.CreateEventW.restype = wt.HANDLE
        self.kernel.WaitForMultipleObjects.argtypes = [wt.DWORD, ctypes.POINTER(wt.HANDLE), wt.BOOL, wt.DWORD]
        self.kernel.WaitForMultipleObjects.restype = wt.DWORD
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel.CloseHandle.restype = wt.BOOL


class _RegWatch:
    def __init__(self, label, hive, path):
        self.label = label
        self.hive = hive
        self.path = path
        self.handle = None
        self.event = None
        self.snap = None
        self.mode = "missing"
        self.next_check = 0.0
        self.next_poll = 0.0


class RegistrySource(Source):
    name = SRC_REG

    def start(self):
        self.watches = []
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        roots = list(REG_ROOTS)
        for text in self.session.options.get("watch_keys", []):
            hive, path = split_reg_path(text)
            if hive_handle(hive) is not None and path and (hive, path) not in roots:
                roots.append((hive, path))
        for hive, path in roots:
            self.watches.append(_RegWatch("%s\\%s" % (hive, path), hive_handle(hive), path))
        self.api = _RegApi()
        self.status_note = None
        self.status("starting", "reading keys")
        self.spawn(self._run, "watch")

    def _close_handle(self, watch):
        if watch.handle is not None:
            try:
                watch.handle.Close()
            except OSError:
                pass
            watch.handle = None

    def _arm(self, watch):
        if watch.handle is None or not watch.event:
            return False
        try:
            code = self.api.advapi.RegNotifyChangeKeyValue(int(watch.handle), True, REG_NOTIFY_FILTER,
                                                           watch.event, True)
        except Exception:
            return False
        return code == 0

    def _open(self, watch, initial):
        now = time.time()
        try:
            handle = winreg.OpenKey(watch.hive, watch.path, 0, winreg.KEY_READ)
        except OSError:
            watch.mode = "missing"
            watch.next_check = now + 2.0
            return
        try:
            snap = read_reg_tree(watch.hive, watch.path)
        except OSError:
            handle.Close()
            watch.mode = "missing"
            watch.next_check = now + 2.0
            return
        self._close_handle(watch)
        watch.handle = handle
        if watch.snap is None and not initial:
            self.emit(KIND_REG, "%s created" % watch.label, CHANGE, detail="Key: " + watch.label)
            for change in reg_diff((set(), {}), snap):
                if change[0] != "key added" or change[1]:
                    self._report(watch, change)
        elif watch.snap is not None:
            for change in reg_diff(watch.snap, snap):
                self._report(watch, change)
        watch.snap = snap
        if not watch.event:
            watch.event = self.api.kernel.CreateEventW(None, False, False, None)
        watch.mode = "notify" if self._arm(watch) else "poll"
        watch.next_poll = now + 1.0
        watch.next_check = now + 5.0

    def _rescan(self, watch):
        try:
            snap = read_reg_tree(watch.hive, watch.path)
        except OSError:
            snap = None
        if snap is None:
            if watch.snap is not None:
                self.emit(KIND_REG, "%s deleted" % watch.label, CHANGE, detail="Key: " + watch.label)
            watch.snap = None
            self._close_handle(watch)
            watch.mode = "missing"
            watch.next_check = time.time() + 2.0
            return
        if watch.snap is not None:
            for change in reg_diff(watch.snap, snap):
                self._report(watch, change)
        watch.snap = snap

    def _report(self, watch, change):
        what, sub, name, old, new = change
        key = watch.label + ("\\" + sub if sub else "")
        if what == "key added":
            self.emit(KIND_REG, "%s created" % key, CHANGE, detail="Key: " + key)
            return
        if what == "key deleted":
            self.emit(KIND_REG, "%s deleted" % key, CHANGE, detail="Key: " + key)
            return
        label = name if name else "(Default)"
        detail = ["Key: " + key, "Value: " + label]
        if what == "value added":
            text = "%s [%s] added: %s" % (key, label, format_reg_value(name, new[0], new[1]))
            detail.append("New: " + full_reg_value(name, new[0], new[1]))
        elif what == "value deleted":
            text = "%s [%s] deleted, was %s" % (key, label, format_reg_value(name, old[0], old[1]))
            detail.append("Old: " + full_reg_value(name, old[0], old[1]))
        else:
            text = "%s [%s]: %s -> %s" % (key, label, format_reg_value(name, old[0], old[1], 100),
                                          format_reg_value(name, new[0], new[1], 100))
            detail.append("Old: " + full_reg_value(name, old[0], old[1]))
            detail.append("New: " + full_reg_value(name, new[0], new[1]))
        self.emit(KIND_REG, text, CHANGE, detail="\n".join(detail))

    def _update_status(self):
        missing = sum(1 for watch in self.watches if watch.mode == "missing")
        watched = len(self.watches) - missing
        note = plural(watched, "key")
        if missing:
            note += ", %d not there yet" % missing
        if note != self.status_note:
            self.status_note = note
            self.status("running", note)

    def _run(self):
        try:
            for watch in self.watches:
                self._open(watch, True)
            self._update_status()
            missing = [watch.label for watch in self.watches if watch.mode == "missing"]
            detail = "\n".join(watch.label for watch in self.watches)
            if missing:
                detail += "\n\nNot there yet:\n" + "\n".join(missing)
            self.note("watching " + plural(len(self.watches), "key"), INFO, detail)
            last_full = time.time()
            while not self.stopping():
                armed = [watch for watch in self.watches if watch.mode == "notify"]
                if armed:
                    handles = (wt.HANDLE * len(armed))(*[watch.event for watch in armed])
                    code = self.api.kernel.WaitForMultipleObjects(len(armed), handles, False, 500)
                else:
                    self.wait(0.5)
                    code = WAIT_TIMEOUT
                if self.stopping():
                    break
                if code < len(armed):
                    watch = armed[code]
                    if not self._arm(watch):
                        watch.mode = "poll"
                    self._rescan(watch)
                now = time.time()
                for watch in self.watches:
                    if watch.mode == "missing":
                        if now >= watch.next_check:
                            self._open(watch, False)
                    elif watch.mode == "poll":
                        if now >= watch.next_poll:
                            watch.next_poll = now + 1.0
                            self._rescan(watch)
                        if watch.mode == "poll" and now >= watch.next_check:
                            self._open(watch, False)
                if now - last_full >= 15.0:
                    last_full = now
                    for watch in self.watches:
                        if watch.mode == "notify":
                            self._rescan(watch)
                self._update_status()
        finally:
            for watch in self.watches:
                self._close_handle(watch)
                if watch.event:
                    self.api.kernel.CloseHandle(watch.event)
                    watch.event = None


def default_watch_folders():
    out = []
    roaming = os.environ.get("APPDATA")
    local = os.environ.get("LOCALAPPDATA")
    if roaming:
        out.append(os.path.join(roaming, "Microsoft", "Windows", "Themes"))
    if local:
        out.append(os.path.join(local, "Microsoft", "Windows", "Themes"))
        out.append(os.path.join(local, "Packages", "Microsoft.Windows.Photos_8wekyb3d8bbwe"))
        out.append(os.path.join(local, "Microsoft", "Windows", "Explorer"))
    return out


class _FolderHandler(FileSystemEventHandler):
    def __init__(self, owner):
        self.owner = owner

    def on_any_event(self, event):
        self.owner.on_change(event.event_type, event.src_path, getattr(event, "dest_path", ""),
                             event.is_directory)


class FilesSource(Source):
    name = SRC_FILES
    observer = None

    def start(self):
        self.observer = None
        folders = []
        wanted = default_watch_folders() + list(self.session.options.get("watch_folders", []))
        for path in wanted:
            if path and os.path.isdir(path) and path not in folders:
                folders.append(path)
        self.folders = folders
        if not folders:
            self.status("off", "no folders found")
            self.note("none of the watched folders exist", INFO, "\n".join(wanted))
            return
        if Observer is not None:
            self.observer = Observer()
            handler = _FolderHandler(self)
            count = 0
            for path in folders:
                try:
                    self.observer.schedule(handler, path, recursive=True)
                    count += 1
                except Exception as exc:
                    LOG.warning("Folder %s could not be watched: %s", path, exc)
            self.observer.start()
            self.status("running", plural(count, "folder"))
        else:
            self.spawn(self._poll, "poll")
            self.status("warn", "%s, checked every second" % plural(len(folders), "folder"))
        self.note("watching " + plural(len(folders), "folder"), INFO, "\n".join(folders))

    def stop(self):
        if self.observer is not None:
            try:
                self.observer.stop()
            except Exception:
                pass

    def join(self, timeout):
        if self.observer is not None:
            try:
                self.observer.join(timeout)
            except Exception:
                pass
        Source.join(self, timeout)

    def on_change(self, kind, src, dst, is_dir):
        if kind not in ("created", "modified", "deleted", "moved"):
            return
        if is_dir and kind == "modified":
            return
        src = os.fsdecode(src) if src else ""
        dst = os.fsdecode(dst) if dst else ""
        now = time.time()
        noun = "Folder" if is_dir else "File"
        if kind == "created":
            text = "%s created: %s" % (noun, src)
        elif kind == "modified":
            text = "File changed: %s" % src
        elif kind == "deleted":
            text = "%s deleted: %s" % (noun, src)
        else:
            text = "%s renamed: %s -> %s" % (noun, src, dst)
        detail = []
        if not is_dir and kind != "deleted":
            try:
                detail.append("Size: %d bytes" % os.path.getsize(dst or src))
            except OSError:
                pass
        self.emit(KIND_FILE, text, CHANGE, detail="\n".join(detail), ts=now)

    def _snapshot(self):
        out = {}
        for root in self.folders:
            for base, _dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(base, name)
                    try:
                        info = os.stat(path)
                    except OSError:
                        continue
                    out[path] = (info.st_size, info.st_mtime_ns)
                    if len(out) >= 20000:
                        return out
        return out

    def _poll(self):
        before = self._snapshot()
        while not self.wait(1.0):
            after = self._snapshot()
            for path, info in after.items():
                if path not in before:
                    self.on_change("created", path, "", False)
                elif before[path] != info:
                    self.on_change("modified", path, "", False)
            for path in before:
                if path not in after:
                    self.on_change("deleted", path, "", False)
            before = after


KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"


class EtwProcessFeed:
    session_name = "Bastard Process Trace"

    def __init__(self, owner):
        self.owner = owner
        self.job = None

    def _stop_session(self):
        try:
            etw_core.ETW(session_name=self.session_name).control_stop(etw_core.TraceProperties())
        except Exception:
            pass

    def start(self):
        self._stop_session()
        provider = etw_core.ProviderInfo("Microsoft-Windows-Kernel-Process", EtwGuid(KERNEL_PROCESS_GUID), 4, 0x10)
        self.job = etw_core.ETW(session_name=self.session_name, providers=[provider],
                                event_callback=self._on_event, event_id_filters=[1, 2])
        try:
            self.job.start()
        except Exception:
            self.stop()
            raise

    def stop(self):
        job, self.job = self.job, None
        if job is not None:
            worker = threading.Thread(target=self._stop_job, args=(job,), name="kernel trace stop", daemon=True)
            worker.start()
            worker.join(10.0)
            if worker.is_alive():
                LOG.warning("Kernel process trace is still stopping after 10 seconds")
        self._stop_session()

    @staticmethod
    def _stop_job(job):
        try:
            job.stop()
        except Exception as exc:
            LOG.warning("Kernel process trace did not stop cleanly: %s", exc)

    def _on_event(self, item):
        try:
            event_id, data = item
            header = data.get("EventHeader") or {}
            raw_time = header.get("TimeStamp")
            ts = filetime_to_epoch(raw_time) if raw_time else time.time()
            if abs(ts - time.time()) > 3600:
                ts = time.time()
            fields = {str(key).lower(): value for key, value in data.items()}
            pid = as_int(fields.get("processid"), 0)
            image = str(fields.get("imagename") or "")
            if event_id == 1:
                self.owner.etw_started(pid, as_int(fields.get("parentprocessid"), 0), image, ts,
                                       str(fields.get("packagefullname") or ""))
            elif event_id == 2:
                self.owner.etw_exited(pid, as_int(fields.get("exitcode")), image, ts)
        except Exception:
            LOG.exception("Kernel process event could not be read")


def _safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def process_label(name, pid):
    if name:
        return "%s (PID %d)" % (name, pid)
    return "PID %d" % pid


def process_table(known=None):
    table = {}
    if psutil is None:
        return table
    for pid in psutil.pids():
        old = known.get(pid) if known else None
        if old is not None:
            table[pid] = old
            continue
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                info = {"pid": pid, "name": _safe(proc.name, "") or "", "ctime": _safe(proc.create_time, 0.0) or 0.0,
                        "ppid": _safe(proc.ppid, 0) or 0}
        except Exception:
            continue
        table[pid] = info
    return table


class ProcessSource(Source):
    name = SRC_PROC
    etw = None
    lock = None

    def start(self):
        self.lock = threading.Lock()
        self.known = {}
        self.reported = {}
        self.ended = {}
        self.pending = []
        self.etw = None
        self.etw_active = False
        self.etw_hits = 0
        self.etw_misses = 0
        can_etw = IS_WIN and etw_core is not None and EtwGuid is not None and self.session.admin
        if psutil is None and not can_etw:
            self.status("failed", "psutil missing")
            return
        self.known = process_table()
        for pid, info in self.known.items():
            PROCESS_NAMES.put(pid, info["name"])
        mode = "psutil"
        if can_etw:
            try:
                self.etw = EtwProcessFeed(self)
                self.etw.start()
                self.etw_active = True
                mode = "kernel events and psutil"
            except Exception as exc:
                LOG.warning("Kernel process trace could not start: %s", exc)
                self.etw = None
                self.note("kernel process events are not available (%s)" % one_line(exc, 120), WARN)
        elif IS_WIN:
            mode = "psutil (not administrator)"
        if psutil is not None:
            self.spawn(self._poll, "poll")
        self.status("running", mode)

    def _poll(self):
        while not self.wait(0.5):
            now = time.time()
            try:
                current = process_table(self.known)
            except Exception as exc:
                LOG.warning("Process list could not be read: %s", exc)
                continue
            for pid, info in current.items():
                if pid in self.known:
                    continue
                PROCESS_NAMES.put(pid, info["name"])
                self._new(info, now)
            for pid, info in self.known.items():
                if pid not in current:
                    self._gone(info, now)
            self.known = current
            self._flush(now)

    def _new(self, info, now):
        if self.etw_active:
            with self.lock:
                self.pending.append((now + 3.0, "start", info))
        else:
            self._psutil_start(info)

    def _gone(self, info, now):
        if self.etw_active:
            with self.lock:
                self.pending.append((now + 3.0, "exit", info))
        else:
            self._psutil_exit(info, now)

    def _flush(self, now):
        with self.lock:
            due = [item for item in self.pending if item[0] <= now]
            self.pending = [item for item in self.pending if item[0] > now]
            if len(self.reported) > 20000:
                self.reported.clear()
                self.ended.clear()
        for when, what, info in due:
            if what == "start":
                self._psutil_start(info)
            else:
                self._psutil_exit(info, when - 3.0)

    def _psutil_start(self, info):
        pid = info["pid"]
        with self.lock:
            seen = self.reported.get(pid)
            if seen is not None and abs(seen - info["ctime"]) < 2.0:
                return
            self.reported[pid] = info["ctime"]
            silent = self.etw_active and self.etw_hits == 0
            if silent:
                self.etw_misses += 1
        if silent and self.etw_misses == 3:
            self.etw_active = False
            self.status("warn", "psutil, kernel events silent")
            self.note("kernel process events stayed silent, so short-lived processes may be missed", WARN)
        self._emit_start(pid, info["ppid"], info["name"], "", info["ctime"] or time.time(), "")

    def _psutil_exit(self, info, when):
        pid = info["pid"]
        with self.lock:
            end = self.ended.get(pid)
            if end is not None and end >= info["ctime"] - 1.0:
                return
            self.ended[pid] = when
        lived = when - info["ctime"] if info["ctime"] else None
        self._emit_exit(pid, info["name"], None, lived, when)

    def etw_started(self, pid, ppid, image, ts, package):
        if not pid:
            return
        with self.lock:
            self.etw_hits += 1
            seen = self.reported.get(pid)
            if seen is not None and abs(seen - ts) < 2.0:
                return
            self.reported[pid] = ts
        path = self.session.devices.to_dos(image) if image else ""
        name = os.path.basename(path) if path else ""
        PROCESS_NAMES.put(pid, name)
        self._emit_start(pid, ppid, name, path, ts, package)

    def etw_exited(self, pid, code, image, ts):
        if not pid:
            return
        with self.lock:
            self.etw_hits += 1
            self.ended[pid] = ts
            started = self.reported.get(pid)
        info = self.known.get(pid)
        name = os.path.basename(self.session.devices.to_dos(image)) if image else ""
        if not name:
            name = info["name"] if info else PROCESS_NAMES.get(pid)
        if started is None and info is not None:
            started = info["ctime"]
        lived = ts - started if started else None
        self._emit_exit(pid, name, code, lived, ts)

    def _emit_start(self, pid, ppid, name, path, ts, package):
        cmd = ""
        if psutil is not None:
            proc = _safe(lambda: psutil.Process(pid))
            if proc is not None:
                name = name or _safe(proc.name, "")
                path = path or _safe(proc.exe, "")
                args = _safe(proc.cmdline, [])
                cmd = subprocess.list2cmdline(args) if args else ""
                ppid = ppid or _safe(proc.ppid, 0)
        parent = PROCESS_NAMES.get(ppid) if ppid else ""
        text = "Started " + process_label(name, pid)
        if ppid:
            text += " by " + process_label(parent, ppid)
        detail = []
        if path:
            detail.append("Path: " + path)
        if cmd:
            detail.append("Command line: " + cmd)
        if ppid:
            detail.append("Parent: " + process_label(parent, ppid))
        if package:
            detail.append("Package: " + package)
        self.emit(KIND_PROC, text, INFO, pid=pid, proc=name, detail="\n".join(detail), ts=ts)

    def _emit_exit(self, pid, name, code, lived, ts):
        text = "Exited " + process_label(name, pid)
        level = INFO
        if code is not None:
            text += " with exit code %s" % exit_code_text(code)
            if (code & 0xFFFFFFFF) >= 0xC0000000:
                level = WARN
        if lived is not None and lived >= 0:
            text += " after %s" % short_duration(lived)
        self.emit(KIND_PROC, text, level, pid=pid, proc=name, ts=ts)

    def finish(self):
        if self.etw is not None:
            self.etw.stop()
            self.etw = None
        if self.lock is not None:
            self._flush(time.time() + 3600.0)


EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_SYSTEM_DIALOGSTART = 0x0010
EVENT_SYSTEM_DIALOGEND = 0x0011
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002
WM_QUIT = 0x0012
GA_ROOT = 2
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080

if IS_WIN:
    WinEventProc = ctypes.WINFUNCTYPE(None, wt.HANDLE, wt.DWORD, wt.HWND, wt.LONG, wt.LONG, wt.DWORD, wt.DWORD)
    EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
else:
    WinEventProc = None
    EnumWindowsProc = None


class _UserApi:
    def __init__(self):
        user = ctypes.WinDLL("user32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        user.SetWinEventHook.argtypes = [wt.DWORD, wt.DWORD, wt.HMODULE, WinEventProc, wt.DWORD, wt.DWORD, wt.DWORD]
        user.SetWinEventHook.restype = wt.HANDLE
        user.UnhookWinEvent.argtypes = [wt.HANDLE]
        user.UnhookWinEvent.restype = wt.BOOL
        user.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        user.GetMessageW.restype = ctypes.c_int
        user.PeekMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT, wt.UINT]
        user.PeekMessageW.restype = wt.BOOL
        user.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
        user.TranslateMessage.restype = wt.BOOL
        user.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
        user.DispatchMessageW.restype = ctypes.c_ssize_t
        user.PostThreadMessageW.argtypes = [wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM]
        user.PostThreadMessageW.restype = wt.BOOL
        user.InternalGetWindowText.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        user.InternalGetWindowText.restype = ctypes.c_int
        user.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        user.GetClassNameW.restype = ctypes.c_int
        user.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        user.GetWindowThreadProcessId.restype = wt.DWORD
        user.GetAncestor.argtypes = [wt.HWND, wt.UINT]
        user.GetAncestor.restype = wt.HWND
        user.EnumChildWindows.argtypes = [wt.HWND, EnumWindowsProc, wt.LPARAM]
        user.EnumChildWindows.restype = wt.BOOL
        get_long = getattr(user, "GetWindowLongPtrW", None) or user.GetWindowLongW
        get_long.argtypes = [wt.HWND, ctypes.c_int]
        get_long.restype = ctypes.c_ssize_t
        kernel.GetCurrentThreadId.restype = wt.DWORD
        kernel.GetTickCount.restype = wt.DWORD
        self.user = user
        self.kernel = kernel
        self.get_long = get_long


class WindowsSource(Source):
    name = SRC_WIN
    api = None

    def start(self):
        self.api = None
        self.tid = 0
        self.ready = threading.Event()
        self.shown = {}
        self.dialogs = {}
        self.last_front = None
        self.failures = 0
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        self.api = _UserApi()
        self.status("starting", "")
        self.spawn(self._run, "hook")
        self.ready.wait(3.0)

    def stop(self):
        if self.api is None:
            return
        self.ready.wait(2.0)
        if self.tid:
            self.api.user.PostThreadMessageW(self.tid, WM_QUIT, 0, 0)

    def _run(self):
        api = self.api
        self.tid = api.kernel.GetCurrentThreadId()
        msg = wt.MSG()
        api.user.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0)
        self.callback = WinEventProc(self._on_event)
        hooks = []
        ranges = ((EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND),
                  (EVENT_SYSTEM_DIALOGSTART, EVENT_SYSTEM_DIALOGEND),
                  (EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW))
        for low, high in ranges:
            handle = api.user.SetWinEventHook(low, high, None, self.callback, 0, 0,
                                              WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS)
            if handle:
                hooks.append(handle)
        if hooks:
            self.status("running", "windows and dialogs")
        else:
            self.status("failed", "window events not available")
        self.ready.set()
        try:
            while hooks and not self.stopping():
                code = api.user.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if code == 0 or code == -1:
                    break
                api.user.TranslateMessage(ctypes.byref(msg))
                api.user.DispatchMessageW(ctypes.byref(msg))
        finally:
            for handle in hooks:
                api.user.UnhookWinEvent(handle)

    def _text(self, hwnd):
        buf = ctypes.create_unicode_buffer(512)
        count = self.api.user.InternalGetWindowText(hwnd, buf, 512)
        return buf.value[:count].strip() if count > 0 else ""

    def _class(self, hwnd):
        buf = ctypes.create_unicode_buffer(256)
        count = self.api.user.GetClassNameW(hwnd, buf, 256)
        return buf.value[:count] if count > 0 else ""

    def _pid(self, hwnd):
        pid = wt.DWORD(0)
        self.api.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    def _owner(self, hwnd):
        pid = self._pid(hwnd)
        name = PROCESS_NAMES.get(pid)
        host = ""
        if name.lower() == "applicationframehost.exe":
            found = []

            def visit(child, _param):
                other = self._pid(child)
                if other and other != pid:
                    found.append(other)
                    return False
                return True

            walker = EnumWindowsProc(visit)
            self.api.user.EnumChildWindows(hwnd, walker, 0)
            if found:
                host = name
                pid = found[0]
                name = PROCESS_NAMES.get(pid)
        return pid, name, host

    def _dialog_texts(self, hwnd):
        texts = []

        def visit(child, _param):
            if self._class(child).lower() == "static":
                text = self._text(child)
                if text:
                    texts.append(one_line(text, 200))
            return len(texts) < 4

        walker = EnumWindowsProc(visit)
        self.api.user.EnumChildWindows(hwnd, walker, 0)
        return texts

    def _detail(self, hwnd, title, host):
        lines = ["Title: " + (title or "(none)"), "Class: " + self._class(hwnd), "Window: 0x%X" % (hwnd or 0)]
        if host:
            lines.append("Shown by: " + host)
        return "\n".join(lines)

    def _when(self, ms):
        delta = ((self.api.kernel.GetTickCount() - ms) & 0xFFFFFFFF) / 1000.0
        if delta > 30:
            delta = 0.0
        return time.time() - delta

    @staticmethod
    def _suffix(name):
        return " (%s)" % name if name else ""

    def _on_event(self, hook, event, hwnd, id_object, id_child, thread_id, ms):
        try:
            if id_object != 0 or id_child != 0 or not hwnd:
                return
            if event == EVENT_OBJECT_CREATE:
                if self.api.user.GetAncestor(hwnd, GA_ROOT) != hwnd:
                    return
                if self.api.get_long(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW:
                    return
                title = self._text(hwnd)
                pid, name, host = self._owner(hwnd)
                label = title or "(%s)" % (self._class(hwnd) or "window")
                self.emit(KIND_WIN, "Window created: %s%s" % (label, self._suffix(name)), INFO, pid=pid,
                          proc=name, detail=self._detail(hwnd, title, host), ts=self._when(ms))
                return
            if event == EVENT_OBJECT_DESTROY:
                info = self.shown.pop(hwnd, None)
                if info is not None:
                    title, pid, name = info
                    self.emit(KIND_WIN, "Window closed: %s%s" % (title, self._suffix(name)), INFO, pid=pid,
                              proc=name, ts=self._when(ms))
                return
            if event == EVENT_OBJECT_SHOW:
                if self.api.user.GetAncestor(hwnd, GA_ROOT) != hwnd:
                    return
                if self.api.get_long(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW:
                    return
                title = self._text(hwnd)
                if not title:
                    return
                old = self.shown.get(hwnd)
                if old is not None and old[0] == title:
                    return
                pid, name, host = self._owner(hwnd)
                if len(self.shown) > 4000:
                    self.shown.clear()
                self.shown[hwnd] = (title, pid, name)
                self.emit(KIND_WIN, "Window opened: %s%s" % (title, self._suffix(name)), INFO, pid=pid, proc=name,
                          detail=self._detail(hwnd, title, host), ts=self._when(ms))
                return
            if event == EVENT_SYSTEM_FOREGROUND:
                title = self._text(hwnd)
                if (hwnd, title) == self.last_front:
                    return
                self.last_front = (hwnd, title)
                pid, name, host = self._owner(hwnd)
                label = title or "(%s window)" % (self._class(hwnd) or "untitled")
                self.emit(KIND_WIN, "In front: %s%s" % (label, self._suffix(name)), INFO, pid=pid, proc=name,
                          detail=self._detail(hwnd, title, host), ts=self._when(ms))
                return
            if event == EVENT_SYSTEM_DIALOGSTART:
                title = self._text(hwnd)
                pid, name, host = self._owner(hwnd)
                texts = self._dialog_texts(hwnd)
                text = "Dialog opened: %s%s" % (title or "(untitled)", self._suffix(name))
                if texts:
                    text += ": " + " | ".join(texts)
                self.dialogs[hwnd] = (title, pid, name)
                detail = self._detail(hwnd, title, host)
                if texts:
                    detail += "\n\nText:\n" + "\n".join(texts)
                self.emit(KIND_WIN, one_line(text, 400), INFO, pid=pid, proc=name, detail=detail, ts=self._when(ms))
                return
            if event == EVENT_SYSTEM_DIALOGEND:
                info = self.dialogs.pop(hwnd, None)
                if info is None:
                    pid, name, _host = self._owner(hwnd)
                    info = (self._text(hwnd), pid, name)
                title, pid, name = info
                self.emit(KIND_WIN, "Dialog closed: %s%s" % (title or "(untitled)", self._suffix(name)), INFO,
                          pid=pid, proc=name, ts=self._when(ms))
        except Exception:
            self.failures += 1
            if self.failures <= 5:
                LOG.exception("Window event could not be read")


EVENT_CHANNELS = (
    "Application",
    "System",
    "Microsoft-Windows-AppModel-Runtime/Admin",
    "Microsoft-Windows-AppXDeployment/Operational",
    "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-Shell-Core/Operational",
    "Microsoft-Windows-TWinUI/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
)
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
EVENT_LEVELS = {0: "Information", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
BACKFILL_MS = 60000
EVENT_SPLIT_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)


def find_wevtutil():
    path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wevtutil.exe")
    if os.path.isfile(path):
        return path
    return shutil.which("wevtutil") or ""


def decode_tool_output(raw):
    if not raw:
        return ""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if IS_WIN:
        try:
            return raw.decode("cp%d" % ctypes.windll.kernel32.GetOEMCP())
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _node_text(node):
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def event_record(element):
    system = element.find(EVENT_NS + "System")
    if system is None:
        return None
    provider = system.find(EVENT_NS + "Provider")
    created = system.find(EVENT_NS + "TimeCreated")
    execution = system.find(EVENT_NS + "Execution")
    record = {
        "provider": provider.get("Name", "") if provider is not None else "",
        "id": as_int(_node_text(system.find(EVENT_NS + "EventID")), 0),
        "level": as_int(_node_text(system.find(EVENT_NS + "Level")), 4),
        "record": as_int(_node_text(system.find(EVENT_NS + "EventRecordID")), 0),
        "channel": _node_text(system.find(EVENT_NS + "Channel")),
        "time": parse_system_time(created.get("SystemTime", "")) if created is not None else None,
        "pid": as_int(execution.get("ProcessID"), 0) if execution is not None else 0,
        "message": "", "level_name": "", "task": "", "data": [],
    }
    rendering = element.find(EVENT_NS + "RenderingInfo")
    if rendering is not None:
        record["message"] = _node_text(rendering.find(EVENT_NS + "Message"))
        record["level_name"] = _node_text(rendering.find(EVENT_NS + "Level"))
        record["task"] = _node_text(rendering.find(EVENT_NS + "Task"))
    data = element.find(EVENT_NS + "EventData")
    if data is not None:
        for item in data:
            record["data"].append((item.get("Name", ""), _node_text(item)))
    else:
        user = element.find(EVENT_NS + "UserData")
        if user is not None:
            for item in user.iter():
                if len(item) == 0 and _node_text(item):
                    record["data"].append((_local(item.tag), _node_text(item)))
    return record


def parse_events_xml(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        elements = list(ET.fromstring("<Events>" + text + "</Events>"))
    except ET.ParseError:
        elements = []
        for match in EVENT_SPLIT_RE.finditer(text):
            try:
                elements.append(ET.fromstring(match.group(0)))
            except ET.ParseError:
                continue
    records = []
    for element in elements:
        record = event_record(element)
        if record is not None:
            records.append(record)
    return records


def short_channel(name):
    prefix = "Microsoft-Windows-"
    return name[len(prefix):] if name.startswith(prefix) else name


def structured_query(selects):
    parts = ['<QueryList><Query Id="0" Path="%s">' % xml_escape(selects[0][0], {'"': "&quot;"})]
    for channel, xpath in selects:
        parts.append('<Select Path="%s">%s</Select>' % (xml_escape(channel, {'"': "&quot;"}), xml_escape(xpath)))
    parts.append("</Query></QueryList>")
    return "".join(parts)


def event_log_text(record):
    number = record["level"]
    label = record["level_name"] or EVENT_LEVELS.get(number, "Level %d" % number)
    message = record["message"].strip()
    first = message.splitlines()[0].strip() if message else ""
    if not first and record["data"]:
        first = ", ".join(("%s=%s" % (k, v)) if k else v for k, v in record["data"][:4])
    text = "%s: %s %d from %s" % (short_channel(record["channel"]), label, record["id"], record["provider"] or "?")
    if first:
        text += ": " + one_line(first, 240)
    if number in (1, 2):
        level = ERROR
    elif number == 3:
        level = WARN
    else:
        level = INFO
    return text, level


class EventLogSource(Source):
    name = SRC_LOG

    def start(self):
        self.channels = []
        self.last = {}
        self.failures = 0
        self.one_by_one = False
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        self.tool = find_wevtutil()
        if not self.tool:
            self.status("failed", "wevtutil not found")
            return
        self.query_path = os.path.join(DATA_DIR, "eventlog_query_%d.xml" % os.getpid())
        self.status("starting", "opening logs")
        self.spawn(self._run, "poll")

    def _run(self):
        skipped = []
        for channel in EVENT_CHANNELS:
            if self.stopping():
                return
            state = self._channel_state(channel)
            if state == "enabled":
                self.channels.append(channel)
            else:
                skipped.append("%s (%s)" % (channel, state))
        for channel in self.channels:
            self.last[channel] = self._newest(channel)
        if not self.channels:
            self.status("failed", "no logs could be read")
            return
        self.status("running", plural(len(self.channels), "log"))
        detail = "\n".join(self.channels)
        if skipped:
            detail += "\n\nSkipped:\n" + "\n".join(skipped)
        self.note("watching " + plural(len(self.channels), "log"), INFO, detail)
        try:
            self._backfill()
            while not self.wait(2.0):
                self._poll()
            self._poll()
        finally:
            try:
                os.remove(self.query_path)
            except OSError:
                pass

    def _channel_state(self, channel):
        try:
            result = run_hidden([self.tool, "gl", channel], 20)
        except Exception:
            return "not readable"
        if result.returncode != 0:
            return "not found"
        match = re.search(r"^\s*enabled:\s*(\w+)", decode_tool_output(result.stdout), re.M | re.I)
        if match and match.group(1).lower() == "false":
            return "turned off in Windows"
        return "enabled"

    def _newest(self, channel):
        try:
            result = run_hidden([self.tool, "qe", channel, "/c:1", "/rd:true", "/f:xml"], 20)
        except Exception:
            return 0
        if result.returncode != 0:
            return 0
        records = parse_events_xml(decode_tool_output(result.stdout))
        return max((record["record"] for record in records), default=0)

    def _query(self, selects, count):
        if not self.one_by_one:
            try:
                with open(self.query_path, "w", encoding="utf-8") as fh:
                    fh.write(structured_query(selects))
                result = run_hidden([self.tool, "qe", self.query_path, "/sq:true", "/f:RenderedXml",
                                     "/c:%d" % count], 40)
                if result.returncode == 0:
                    return parse_events_xml(decode_tool_output(result.stdout)), ""
                error = one_line(decode_tool_output(result.stderr) or decode_tool_output(result.stdout), 200)
            except Exception as exc:
                error = one_line(exc, 200)
            self.one_by_one = True
            LOG.warning("The combined event log query failed, so each log is read on its own: %s", error)
        records = []
        for channel, xpath in selects:
            try:
                result = run_hidden([self.tool, "qe", channel, "/q:" + xpath, "/f:RenderedXml", "/c:%d" % count], 40)
            except Exception as exc:
                return None, one_line(exc, 200)
            if result.returncode != 0:
                return None, one_line(decode_tool_output(result.stderr) or decode_tool_output(result.stdout), 200)
            records.extend(parse_events_xml(decode_tool_output(result.stdout)))
        return records, ""

    def _backfill(self):
        xpath = "*[System[(EventRecordID <= %d) and TimeCreated[timediff(@SystemTime) <= %d]]]"
        selects = [(channel, xpath % (self.last[channel], BACKFILL_MS)) for channel in self.channels
                   if self.last.get(channel)]
        if not selects:
            return
        records, error = self._query(selects, 300)
        if records is None:
            LOG.warning("Event log backfill failed: %s", error)
            return
        for record in records:
            self._report(record, True)

    def _poll(self):
        selects = [(channel, "*[System[(EventRecordID > %d)]]" % self.last.get(channel, 0)) for channel in self.channels]
        records, error = self._query(selects, 500)
        if records is None:
            self.failures += 1
            if self.failures == 3:
                self.status("warn", "reading fails")
                self.note("the logs could not be read: %s" % error, WARN)
            return
        if self.failures >= 3:
            self.status("running", plural(len(self.channels), "log"))
        self.failures = 0
        for record in records:
            channel = record["channel"]
            if channel in self.last and record["record"] <= self.last[channel]:
                continue
            self.last[channel] = max(self.last.get(channel, 0), record["record"])
            self._report(record, False)

    def _report(self, record, before):
        text, level = event_log_text(record)
        lines = ["Log: " + record["channel"], "Provider: " + record["provider"], "Event ID: %d" % record["id"],
                 "Level: " + (record["level_name"] or EVENT_LEVELS.get(record["level"], str(record["level"])))]
        if record["task"]:
            lines.append("Task: " + record["task"])
        lines.append("Record: %d" % record["record"])
        if record["pid"]:
            lines.append("Logged by PID %d" % record["pid"])
        if before:
            lines.append("Logged before Start")
        if record["message"]:
            lines.append("")
            lines.append(record["message"])
        if record["data"]:
            lines.append("")
            for key, value in record["data"][:40]:
                lines.append("%s: %s" % (key, value) if key else value)
        self.emit(KIND_LOG, text, level, pid=record["pid"] or None, detail="\n".join(lines),
                  ts=record["time"] or time.time())


PROCMON_NAMES = ("Procmon64.exe", "Procmon.exe", "Procmon64a.exe")
PROCMON_SKIP = frozenset(("procmon.exe", "procmon64.exe", "procmon64a.exe"))
PROCMON_DENIED = frozenset(("ACCESS DENIED", "PRIVILEGE NOT HELD"))
PROCMON_REG_WRITES = frozenset(("RegSetValue", "RegDeleteValue", "RegDeleteKey", "RegRenameKey", "RegSetKeySecurity"))
PROCMON_FILE_WRITES = frozenset(("WriteFile", "SetDispositionInformationFile", "SetDispositionInformationEx",
                                 "SetRenameInformationFile", "SetRenameInformationEx",
                                 "SetRenameInformationExBypassAccessCheck", "SetSecurityFile"))
PROCMON_PROCESS_OPS = frozenset(("Process Create", "Process Exit", "Process Start", "Thread Create", "Thread Exit",
                                 "Load Image", "Process Statistics", "Process Profiling", "Thread Profiling"))
PROCMON_ROW_LIMIT = 1000000
PROCMON_KEEP = 5
TIME_OF_DAY_RE = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*([AaPp])?")


def find_procmon():
    folders = [program_dir(), DESKTOP, os.getcwd(), "C:\\Tools", "C:\\Sysinternals", "C:\\SysinternalsSuite"]
    folders += [path for path in os.environ.get("PATH", "").split(os.pathsep) if path]
    for folder in folders:
        for name in PROCMON_NAMES:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
    return ""


def procmon_kind(operation):
    if operation.startswith("Reg"):
        return KIND_REG
    if operation.startswith("TCP") or operation.startswith("UDP"):
        return KIND_NET
    if operation in PROCMON_PROCESS_OPS:
        return KIND_PROC
    return KIND_FILE


class ProcmonDigest:
    def __init__(self, own_pid, limit=PROCMON_ROW_LIMIT):
        self.own_pid = own_pid
        self.limit = limit
        self.rows = []
        self.total = 0
        self.over = 0
        self.denied = 0
        self.reg_writes = 0
        self.file_writes = 0
        self.reads = 0

    def add(self, ts, proc, pid, operation, path, result):
        self.total += 1
        if pid == self.own_pid:
            return
        name = (proc or "").lower()
        if name in PROCMON_SKIP:
            return
        kind = procmon_kind(operation)
        if result in PROCMON_DENIED:
            level, tag = ERROR, "denied"
        elif operation in PROCMON_REG_WRITES:
            level, tag = CHANGE, "registry"
        elif operation in PROCMON_FILE_WRITES:
            level, tag = CHANGE, "file"
        else:
            level, tag = INFO, "read"
        if len(self.rows) >= self.limit:
            self.over += 1
            return
        self.rows.append([ts, proc, pid, operation, path, result, kind, level])
        if tag == "denied":
            self.denied += 1
        elif tag == "registry":
            self.reg_writes += 1
        elif tag == "file":
            self.file_writes += 1
        else:
            self.reads += 1

    def ordered(self):
        return sorted(self.rows, key=lambda row: row[0])


def procmon_time_of_day(text, day_start):
    match = TIME_OF_DAY_RE.search(text or "")
    if not match:
        return day_start
    hour, minute, second = int(match.group(1)), int(match.group(2)), int(match.group(3))
    fraction = match.group(4) or ""
    suffix = (match.group(5) or "").lower()
    if suffix == "p" and hour < 12:
        hour += 12
    elif suffix == "a" and hour == 12:
        hour = 0
    base = datetime.fromtimestamp(day_start).replace(hour=hour % 24, minute=minute, second=second, microsecond=0)
    value = base.timestamp()
    if fraction:
        value += int(fraction) / float(10 ** len(fraction))
    if value < day_start - 3600:
        value += 86400
    return value


def procmon_csv_rows(path):
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        encoding = "utf-16"
    elif head.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    elif b"\x00" in head[:200]:
        encoding = "utf-16-le"
    else:
        encoding = "utf-8"
    with open(path, "r", encoding=encoding, errors="replace", newline="") as fh:
        first = fh.readline()
    delimiter = "\t" if first.count("\t") > first.count(",") else ","
    with open(path, "r", encoding=encoding, errors="replace", newline="") as fh:
        for row in csv.DictReader(fh, delimiter=delimiter):
            yield row


class ProcMonSource(Source):
    name = SRC_PM
    proc = None

    def start(self):
        self.proc = None
        self.exe = ""
        self.pml = ""
        self.launched = 0.0
        self.capturing = False
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        self.exe = find_procmon()
        if not self.exe:
            self.status("off", "Procmon64.exe not found")
            self.note("put Procmon64.exe next to Bastard to record a ProcMon capture", INFO,
                      "Bastard looks next to itself, on the Desktop, in C:\\Tools, C:\\Sysinternals and on the PATH.")
            return
        if not self.session.admin:
            self.status("off", "needs administrator")
            self.note("needs Bastard to run as administrator", WARN)
            return
        self.status("starting", "launching")
        self.spawn(self._launch, "launch")

    def _tidy(self):
        try:
            names = [n for n in os.listdir(TRACE_DIR) if n.startswith("Bastard_") and n.lower().endswith((".pml", ".csv"))]
        except OSError:
            return
        stems = sorted({os.path.splitext(n)[0] for n in names})
        for stem in stems[: max(0, len(stems) - (PROCMON_KEEP - 1))]:
            for ext in (".pml", ".csv"):
                try:
                    os.remove(os.path.join(TRACE_DIR, stem + ext))
                except OSError:
                    pass

    def _launch(self):
        os.makedirs(TRACE_DIR, exist_ok=True)
        self._tidy()
        self.pml = os.path.join(TRACE_DIR, "Bastard_%s.pml" % self.session.stamp_text)
        self.launched = time.time()
        if self.stopping():
            return
        self.proc = subprocess.Popen([self.exe, "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", self.pml],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, cwd=os.path.dirname(self.exe))
        end = time.time() + 25.0
        while time.time() < end and not self.stopping():
            if os.path.isfile(self.pml) and os.path.getsize(self.pml) > 0:
                break
            time.sleep(0.25)
        if os.path.isfile(self.pml):
            self.capturing = True
            self.session.pml_path = self.pml
            self.status("running", "capturing")
            self.note("capturing", INFO, "Capture file: %s\nProcMon: %s" % (self.pml, self.exe))
        elif not self.stopping():
            self.status("failed", "capture did not start")
            self.note("the capture did not start", ERROR, "ProcMon: " + self.exe)

    def _procmon_pids(self):
        pids = set()
        if self.proc is not None and self.proc.poll() is None:
            pids.add(self.proc.pid)
        for pid, info in process_table().items():
            if info["name"].lower() in PROCMON_SKIP and info["ctime"] >= self.launched - 2:
                pids.add(pid)
        return pids

    def _close(self, abort):
        pids = self._procmon_pids()
        if not pids:
            return True
        for pid in pids:
            _safe(lambda: run_hidden(["taskkill", "/PID", str(pid), "/T"], 15))
        end = time.time() + (5.0 if abort else 45.0)
        while time.time() < end:
            if not self._procmon_pids():
                return True
            time.sleep(0.5)
        for pid in self._procmon_pids():
            _safe(lambda: run_hidden(["taskkill", "/F", "/PID", str(pid), "/T"], 15))
        time.sleep(1.0)
        return False

    def _fix_path(self, path):
        if path.startswith("\\REGISTRY\\") or path.startswith("\\Registry\\"):
            return nice_reg_path(path, self.session.user_sid)
        if path.startswith("\\Device\\"):
            return self.session.devices.to_dos(path)
        return path

    def _progress(self, done, total, last):
        now = time.time()
        if now - last >= 1.0 and total:
            self.status("finishing", "reading %d%%" % (done * 100 // total))
            return now
        return last

    def _read_pml(self, digest):
        if ProcmonLogsReader is None:
            return False, "procmon-parser is missing"
        try:
            with open(self.pml, "rb") as fh:
                reader = ProcmonLogsReader(fh, should_get_stacktrace=False, should_get_details=False)
                total = len(reader)
                if total <= 0:
                    return False, "the capture holds no events"
                last = 0.0
                for index in range(total):
                    if index % 2000 == 0:
                        if self.session.abort_event.is_set():
                            return False, "closed"
                        last = self._progress(index, total, last)
                    ev = reader[index]
                    group = ev.event_class.name
                    if group == "Profiling":
                        digest.total += 1
                        continue
                    operation = getattr(ev.operation, "csv_name", None) or ev.operation.name
                    result = procmon_result_text(ev.result) if procmon_result_text else str(ev.result)
                    digest.add(filetime_to_epoch(ev.date_filetime), ev.process.process_name, ev.process.pid,
                               operation, self._fix_path(ev.path or ""), result)
            return True, plural(total, "event")
        except Exception as exc:
            LOG.exception("ProcMon capture could not be read")
            if digest.total > 0:
                return True, "read %s before an error: %s" % (plural(digest.total, "event"), one_line(exc, 100))
            return False, one_line(exc, 120)

    def _read_csv(self, digest):
        csv_path = os.path.splitext(self.pml)[0] + ".csv"
        self.status("finishing", "exporting CSV")
        try:
            run_hidden([self.exe, "/AcceptEula", "/Quiet", "/Minimized", "/OpenLog", self.pml, "/SaveAs", csv_path], 900)
        except Exception as exc:
            return False, one_line(exc, 120)
        if not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0:
            return False, "ProcMon wrote no CSV"
        count = 0
        for row in procmon_csv_rows(csv_path):
            count += 1
            if count % 5000 == 0 and self.session.abort_event.is_set():
                return False, "closed"
            digest.add(procmon_time_of_day(row.get("Time of Day", ""), self.session.started),
                       row.get("Process Name") or "", as_int(row.get("PID"), 0), (row.get("Operation") or "").strip(),
                       self._fix_path(row.get("Path") or ""), (row.get("Result") or "").strip())
        return count > 0, plural(count, "row")

    def finish(self):
        if self.proc is None:
            return
        abort = self.session.abort_event.is_set()
        self.status("finishing", "closing ProcMon")
        if not self._close(abort):
            self.note("ProcMon did not close in time, so it was stopped", WARN)
        if abort or not self.capturing or not os.path.isfile(self.pml):
            return
        digest = ProcmonDigest(os.getpid())
        ok, info = self._read_pml(digest)
        if not ok and not self.session.abort_event.is_set():
            ok, info = self._read_csv(digest)
        if self.session.abort_event.is_set():
            return
        if not ok:
            self.status("failed", "capture could not be read")
            self.note("the capture could not be read (%s)" % info, ERROR, "Capture file: " + self.pml)
            return
        self._publish(digest, info)

    def _publish(self, digest, info):
        rows = digest.ordered()
        for ts, proc, pid, operation, path, result, kind, level in rows:
            text = "%s %s" % (operation, path) if path else operation
            if result and result != "SUCCESS":
                text += ": " + result
            detail = ["Operation: " + operation, "Path: " + (path or "(none)"), "Result: " + result,
                      "Process: %s (PID %s)" % (proc, pid)]
            self.emit(kind, one_line(text, 600), level, pid=pid, proc=proc, detail="\n".join(detail), ts=ts)
        summary = "read %s, listed %d: %d denied, %d registry writes, %d file writes, %d scope reads" % (
            plural(digest.total, "event"), len(rows), digest.denied, digest.reg_writes, digest.file_writes,
            digest.reads)
        if digest.over:
            summary += ", %d more not listed" % digest.over
        self.note(summary, INFO, "Capture file: %s\nRead: %s" % (self.pml, info))
        for number, start in list(self.session.markers):
            found = sum(1 for row in rows if start < row[0] <= start + MARKER_WINDOW)
            self.hub.emit(SRC_SYSTEM, KIND_MARK, "Marker %d: ProcMon listed %s in the %d seconds after it" % (
                number, plural(found, "event"), MARKER_WINDOW), MARK, ts=start + MARKER_WINDOW + 0.001)
        self.status("done", "%d listed" % len(rows))


def current_wallpaper():
    if not IS_WIN:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    try:
        if ctypes.windll.user32.SystemParametersInfoW(0x0073, 1024, buf, 0):
            return buf.value
    except Exception:
        pass
    return ""


class WallpaperSource(Source):
    name = SRC_WALL

    def start(self):
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        self.spawn(self._run, "poll")

    def _run(self):
        last = current_wallpaper()
        self.status("running", "checked every second")
        self.emit(KIND_DESK, "Wallpaper at start: %s" % (last or "(none)"), INFO)
        while not self.wait(1.0):
            now = current_wallpaper()
            if now != last:
                self.emit(KIND_DESK, "Wallpaper changed: %s -> %s" % (last or "(none)", now or "(none)"), CHANGE)
                last = now



def reg_read_value(hive_const, path, name):
    if winreg is None or hive_const is None:
        return None
    try:
        with winreg.OpenKey(hive_const, path, 0, winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


def reg_key_exists(hive_const, path):
    if winreg is None or hive_const is None:
        return False
    try:
        handle = winreg.OpenKey(hive_const, path, 0, winreg.KEY_READ)
        handle.Close()
        return True
    except OSError:
        return False


def run_text(cmd, timeout):
    try:
        result = run_hidden(cmd, timeout)
    except Exception as exc:
        return None, one_line(exc, 200)
    return result.returncode, decode_tool_output(result.stdout) + decode_tool_output(result.stderr)


ETW_RAW_PROVIDERS = (
    ("Kernel-Registry", "{70EB4F03-C1DE-4F73-A051-33D13D541355}", True),
    ("Kernel-File", "{EDD08927-9CC4-4E65-B970-C2560FB5C289}", True),
    ("Shell-Core", "{30336ED4-E327-447C-9DE0-51B2E6059F02}", False),
    ("Immersive-Shell", "{BC2C92D8-8DB4-4F8B-8D29-8F3A3A0BF1A4}", False),
    ("Themes", "{7B67BEC2-6E2F-4A68-B7E4-9D3E9A4C4C8F}", False),
)
ETW_GUID_NAMES = {guid.upper(): name for name, guid, _kernel in ETW_RAW_PROVIDERS}
ETW_WRITE_MARKS = ("setvalue", "deletevalue", "deletekey", "createkey", "renamekey", "setkeysecurity", "writefile",
                   "setinformation", "setdisposition", "setrename", "deletefile", "setsecurity")
ETW_SKIP_KEYS = frozenset(("EventHeader", "Descriptor", "ProviderId", "ProviderName", "Provider Name", "Task Name"))


class EtwRawSource(Source):
    name = SRC_ETW
    session_name = "Bastard ETW Trace"

    def start(self):
        self.job = None
        self.count = 0
        self.own_pid = os.getpid()
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        if etw_core is None or EtwGuid is None:
            self.status("off", "pywintrace missing")
            self.note("install pywintrace to record the ETW providers", INFO)
            return
        self.status("starting", "opening providers")
        self.spawn(self._run, "trace")

    def _providers(self):
        providers = []
        used = []
        for pname, guid, kernel in ETW_RAW_PROVIDERS:
            if kernel and not self.session.admin:
                continue
            try:
                providers.append(etw_core.ProviderInfo(pname, EtwGuid(guid), 5, 0xffffffffffffffff))
                used.append(pname)
            except Exception as exc:
                self.note("provider %s is not available: %s" % (pname, one_line(exc, 120)), WARN)
        return providers, used

    def _run(self):
        providers, used = self._providers()
        if not providers:
            self.status("off", "no providers available")
            if IS_WIN and not self.session.admin:
                self.note("the kernel providers need administrator, so ETW stayed off", WARN)
            return
        self._stop_session()
        try:
            self.job = etw_core.ETW(session_name=self.session_name, providers=providers, event_callback=self._on)
            self.job.start()
        except Exception as exc:
            self.job = None
            self.status("failed", one_line(exc, 60))
            self.note("the ETW session could not start: %s" % one_line(exc, 200), ERROR)
            return
        self.status("running", ", ".join(used))
        self.note("watching " + plural(len(used), "provider"), INFO, "\n".join(used))
        while not self.stopping():
            self.wait(1.0)

    def _on(self, item):
        try:
            event_id, data = item
        except Exception:
            return
        try:
            if not isinstance(data, dict):
                return
            header = data.get("EventHeader") or {}
            raw_time = header.get("TimeStamp")
            ts = filetime_to_epoch(raw_time) if raw_time else time.time()
            if abs(ts - time.time()) > 86400:
                ts = time.time()
            pid = as_int(header.get("ProcessId"), 0) or as_int(data.get("ProcessId"), 0)
            if pid and pid == self.own_pid:
                return
            provider = data.get("ProviderName") or data.get("Provider Name") or ""
            if not provider:
                provider = ETW_GUID_NAMES.get(str(header.get("ProviderId") or "").upper(), "")
            parts = []
            for key, value in data.items():
                if key in ETW_SKIP_KEYS:
                    continue
                text = one_line(value, 160)
                if text:
                    parts.append("%s=%s" % (key, text))
            detail = " | ".join(parts)
            blob = (str(provider) + " " + detail).lower()
            denied = "denied" in blob or "0x8007" in blob or "0xc0000022" in blob
            write = any(mark in blob for mark in ETW_WRITE_MARKS)
            level = ERROR if denied else (CHANGE if write else INFO)
            label = provider or "ETW"
            low = label.lower()
            kind = KIND_REG if "registry" in low else (KIND_FILE if "file" in low else KIND_ETW)
            body = "Provider: %s\nEvent ID: %s" % (label, event_id)
            if detail:
                body += "\n" + detail
            self.emit(kind, one_line("[%s] %s" % (label, detail or ("event %s" % event_id)), 600), level,
                      pid=pid or None, detail=body, ts=ts)
            self.count += 1
        except Exception:
            pass

    def _stop_session(self):
        try:
            etw_core.ETW(session_name=self.session_name).control_stop(etw_core.TraceProperties())
        except Exception:
            pass

    @staticmethod
    def _stop_job(job):
        try:
            job.stop()
        except Exception as exc:
            LOG.warning("ETW raw trace did not stop cleanly: %s", exc)

    def finish(self):
        job, self.job = self.job, None
        if job is not None:
            worker = threading.Thread(target=self._stop_job, args=(job,), name="etw raw stop", daemon=True)
            worker.start()
            worker.join(10.0)
            if worker.is_alive():
                LOG.warning("ETW raw trace is still stopping after 10 seconds")
        self._stop_session()


WMI_REG_TARGETS = (
    ("HKEY_CURRENT_USER", "Control Panel\\Desktop", "WallPaper"),
    ("HKEY_CURRENT_USER", "Control Panel\\Desktop", "WallpaperStyle"),
    ("HKEY_CURRENT_USER", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers", "BackgroundType"),
    ("HKEY_CURRENT_USER", "Software\\Microsoft\\Windows\\CurrentVersion\\Themes", "CurrentTheme"),
)


class WmiSource(Source):
    name = SRC_WMI

    def start(self):
        self.timeout_exc = None
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        if wmi_module is None or pythoncom is None:
            self.status("off", "wmi or pywin32 missing")
            self.note("install wmi and pywin32 to use the WMI watchers", INFO)
            return
        self.timeout_exc = getattr(wmi_module, "x_wmi_timed_out", None)
        self.status("starting", "connecting")
        self.spawn(self._proc_watch, "process")
        self.spawn(self._reg_watch, "registry")

    def _is_timeout(self, exc):
        return self.timeout_exc is not None and isinstance(exc, self.timeout_exc)

    def _proc_watch(self):
        pythoncom.CoInitialize()
        try:
            conn = wmi_module.WMI()
            watcher = conn.Win32_Process.watch_for("creation")
            self.status("running", "process and registry")
            while not self.stopping():
                try:
                    hit = watcher(timeout_ms=1000)
                except Exception as exc:
                    if self._is_timeout(exc):
                        continue
                    if self.stopping():
                        break
                    self.note("WMI process watcher stopped: %s" % one_line(exc, 200), WARN)
                    break
                if not hit:
                    continue
                pid = as_int(getattr(hit, "ProcessId", 0), 0)
                name = getattr(hit, "Name", "") or ""
                cmd = getattr(hit, "CommandLine", "") or ""
                detail = "Name: %s\nPID: %s\nCommand line: %s" % (name, pid, cmd)
                self.emit(KIND_PROC, "WMI saw a new process: %s" % process_label(name, pid), INFO,
                          pid=pid or None, proc=name, detail=detail)
        except Exception as exc:
            self.status("warn", "process watcher failed")
            self.note("WMI process watcher could not run: %s" % one_line(exc, 200), WARN)
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _reg_watch(self):
        pythoncom.CoInitialize()
        try:
            conn = wmi_module.WMI()
            watchers = []
            for hive, path, name in WMI_REG_TARGETS:
                try:
                    watchers.append((conn.RegistryValueChangeEvent.watch_for(Hive=hive, KeyPath=path, ValueName=name),
                                     hive, path, name))
                except Exception:
                    pass
            if not watchers:
                self.note("WMI registry change events are off here, the Registry source still watches these keys", INFO)
                return
            while not self.stopping():
                for watcher, hive, path, name in watchers:
                    if self.stopping():
                        break
                    try:
                        hit = watcher(timeout_ms=500)
                    except Exception as exc:
                        if self._is_timeout(exc):
                            continue
                        continue
                    if hit:
                        self.emit(KIND_REG, "WMI change: %s\\%s [%s]" % (hive, path, name), CHANGE,
                                  detail="Hive: %s\nKey: %s\nValue: %s" % (hive, path, name))
        except Exception as exc:
            self.note("WMI registry watcher could not run: %s" % one_line(exc, 200), WARN)
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass


PROBE_POLICY_KEYS = (
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop", "NoChangingWallpaper"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "NoDispBackgroundPage"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableLogonBackgroundImage"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "Wallpaper"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "WallpaperStyle"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoLockScreen"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoChangingLockScreen"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoChangingWallpaper"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "LockScreenImage"),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop", "NoChangingWallpaper"),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "NoDispBackgroundPage"),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "Wallpaper"),
    ("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoChangingWallpaper"),
    ("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoLockScreen"),
    ("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoChangingLockScreen"),
    ("HKCU", "SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", "DisableWindowsSpotlightFeatures"),
    ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", "DisableWindowsSpotlightFeatures"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP", "LockScreenImagePath"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP", "LockScreenImageUrl"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP", "DesktopImagePath"),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP", "DesktopImageUrl"),
)
PROBE_APPPRIVACY = ("LetAppsAccessAccountInfo", "LetAppsAccessUserData", "LetAppsAccessPicturesLibrary",
                    "LetAppsAccessDocumentsLibrary", "LetAppsRunInBackground", "LetAppsAccessCamera",
                    "LetAppsAccessLocation")
PROBE_APPPRIVACY_WORDS = {0: "0 (user in control)", 1: "1 (force allow)", 2: "2 (force deny)"}
PROBE_CONSENT = ("userAccountInformation", "picturesLibrary", "documentsLibrary", "broadFileSystemAccess",
                 "graphicsCaptureProgrammatic")
PROBE_DISALLOW = ("photos.exe", "runtimebroker.exe", "systemsettings.exe", "backgroundtaskhost.exe",
                  "applicationframehost.exe", "winrt.runtime.dll")
PROBE_IFEO = ("RuntimeBroker.exe", "SystemSettings.exe", "Photos.exe", "ApplicationFrameHost.exe")
PROBE_SHELL_FOLDERS = ("Desktop", "AppData", "Local AppData", "My Pictures")
PROBE_SHELL_VERBS = (
    ("HKCR", "SystemFileAssociations\\.jpg\\shell\\setaswallpaper"),
    ("HKCR", "SystemFileAssociations\\.jpeg\\shell\\setaswallpaper"),
    ("HKCR", "SystemFileAssociations\\.png\\shell\\setaswallpaper"),
    ("HKCR", "SystemFileAssociations\\image\\shell\\setaswallpaper"),
    ("HKCR", "jpegfile\\shell\\setaswallpaper"),
    ("HKCR", "pngfile\\shell\\setaswallpaper"),
    ("HKCR", "Paint.Picture\\shell\\setaswallpaper"),
    ("HKCU", "Software\\Classes\\SystemFileAssociations\\.jpg\\shell\\setaswallpaper"),
)
PROBE_IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".bmp")
PROBE_SERVICES = ("Themes", "AppXSvc", "ClipSVC", "StateRepository", "TokenBroker", "Dwm", "ShellHWDetection",
                  "ShellExperienceHost")
WINRT_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';",
    "try { [void][Windows.System.UserProfile.UserProfilePersonalizationSettings,Windows.System.UserProfile,"
    "ContentType=WindowsRuntime];",
    "$s=[Windows.System.UserProfile.UserProfilePersonalizationSettings]::IsSupported();",
    "Write-Output ('IsSupported=' + $s); } catch { Write-Output ('ERR:' + $_.Exception.Message) }",
    "try { $img=[Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime]"
    "::OriginalImageFile;",
    "Write-Output ('LockScreenOriginalImageFile=' + $img); } catch { Write-Output ('ERR2:' + $_.Exception.Message) }",
    "try { $pkg=Get-AppxPackage Microsoft.Windows.Photos | Select-Object Name,Status,Version,PackageFullName |",
    "ConvertTo-Json -Compress; Write-Output ('PHOTOS=' + $pkg); } catch { Write-Output ('ERR3:'"
    " + $_.Exception.Message) }",
    "try { $caps=(Get-AppxPackage Microsoft.Windows.Photos).Capabilities;",
    "Write-Output ('PHOTOSCAPS=' + ($caps -join ',')); } catch { Write-Output ('ERR4:' + $_.Exception.Message) }",
)


class ProbeSource(Source):
    name = SRC_PROBE

    def start(self):
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        self.status("starting", "reading settings")
        self.spawn(self._run, "probe")

    def _run(self):
        probes = (self._policy, self._appprivacy, self._consentstore, self._disallowrun, self._ifeo,
                  self._shell_verbs, self._winrt, self._transcode_write, self._acl, self._services,
                  self._explorer_hints, self._shell_folders)
        for probe in probes:
            if self.stopping():
                break
            try:
                probe()
            except Exception as exc:
                self.emit(KIND_PROBE, "probe %s failed: %s" % (probe.__name__, one_line(exc, 160)), WARN)
        self.status("done", "settings read once at start")

    def _say(self, text, level=INFO, detail=""):
        self.emit(KIND_PROBE, one_line(text, 240), level, detail=detail)

    def _policy(self):
        self._say("A: personalization policy keys")
        for hive, path, name in PROBE_POLICY_KEYS:
            value = reg_read_value(hive_handle(hive), path, name)
            if value is None:
                self._say("%s %s [%s] = unset" % (hive, path, name))
            else:
                self._say("%s %s [%s] = %s" % (hive, path, name, value), CHANGE,
                          detail="%s\\%s\nValue: %s = %s" % (hive, path, name, value))

    def _appprivacy(self):
        self._say("B: AppPrivacy policy")
        path = "SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy"
        hive = hive_handle("HKLM")
        if not reg_key_exists(hive, path):
            self._say("AppPrivacy key is not there")
            return
        for name in PROBE_APPPRIVACY:
            value = reg_read_value(hive, path, name)
            if value is None:
                continue
            word = PROBE_APPPRIVACY_WORDS.get(as_int(value), str(value))
            level = ERROR if as_int(value) == 2 else INFO
            self._say("AppPrivacy [%s] = %s" % (name, word), level)

    def _consentstore(self):
        self._say("C: ConsentStore capability access")
        base = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
        for tag in ("HKLM", "HKCU"):
            hive = hive_handle(tag)
            for cap in PROBE_CONSENT:
                value = reg_read_value(hive, base + "\\" + cap, "Value")
                if value is None:
                    self._say("%s %s = unset" % (tag, cap))
                elif str(value) == "Deny":
                    self._say("%s %s = Deny" % (tag, cap), ERROR)
                else:
                    self._say("%s %s = %s" % (tag, cap, value))

    def _disallowrun(self):
        self._say("D: DisallowRun policy")
        hive = hive_handle("HKCU")
        path = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
        flag = reg_read_value(hive, path, "DisallowRun")
        self._say("DisallowRun = %s" % ("unset" if flag is None else flag))
        sub = path + "\\DisallowRun"
        if not reg_key_exists(hive, sub):
            return
        try:
            handle = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
        except OSError:
            return
        with handle:
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                index += 1
                level = ERROR if str(value).lower() in PROBE_DISALLOW else INFO
                self._say("DisallowRun [%s] = %s" % (name, value), level)

    def _ifeo(self):
        self._say("E: Image File Execution Options")
        hive = hive_handle("HKLM")
        base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        for exe in PROBE_IFEO:
            path = base + "\\" + exe
            if not reg_key_exists(hive, path):
                continue
            debugger = reg_read_value(hive, path, "Debugger")
            if debugger:
                self._say("IFEO %s Debugger = %s" % (exe, debugger), ERROR)
            options = reg_read_value(hive, path, "MitigationOptions")
            if options is not None:
                try:
                    number = int.from_bytes(options, "little") if isinstance(options, bytes) else int(options)
                except Exception:
                    number = 0
                blocked = bool(number & (1 << 44))
                self._say("IFEO %s MitigationOptions = 0x%x%s" % (exe, number,
                          " (blocks non Microsoft binaries)" if blocked else ""),
                          WARN if blocked else INFO)

    def _shell_verbs(self):
        self._say("F: set as wallpaper verb and image associations")
        found = 0
        for tag, path in PROBE_SHELL_VERBS:
            hive = hive_handle(tag)
            if not reg_key_exists(hive, path):
                continue
            found += 1
            command = reg_read_value(hive, path + "\\command", "")
            self._say("%s %s command = %s" % (tag, path, command if command else "(default)"), CHANGE)
        if not found:
            self._say("no setaswallpaper verb found in the usual places", ERROR)
        for ext in PROBE_IMAGE_EXTS:
            progid = reg_read_value(hive_handle("HKCR"), ext, "")
            if not progid:
                self._say("%s has no ProgID" % ext, ERROR)
                continue
            verbs = []
            try:
                handle = winreg.OpenKey(hive_handle("HKCR"), "%s\\shell" % progid, 0, winreg.KEY_READ)
            except OSError:
                self._say("%s -> %s but %s\\shell is missing" % (ext, progid, progid), ERROR)
                continue
            with handle:
                index = 0
                while True:
                    try:
                        verbs.append(winreg.EnumKey(handle, index))
                    except OSError:
                        break
                    index += 1
            self._say("%s -> %s verbs: %s" % (ext, progid, ", ".join(verbs[:15]) or "(none)"), CHANGE)

    def _winrt(self):
        self._say("G: WinRT lock screen and Photos package")
        code, out = run_text(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                              "-WindowStyle", "Hidden", "-Command", "".join(WINRT_SCRIPT)], 40)
        if code is None:
            self._say("WinRT read failed: %s" % out, WARN)
            return
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            level = ERROR if "IsSupported=False" in line else (WARN if line.startswith("ERR") else INFO)
            self._say(line, level)

    def _transcode_write(self):
        self._say("H: TranscodedWallpaper write test")
        path = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Themes", "TranscodedWallpaper")
        if not os.path.isfile(path):
            self._say("TranscodedWallpaper is not there: %s" % path, WARN)
            return
        try:
            with open(path, "ab") as handle:
                handle.write(b"")
            self._say("TranscodedWallpaper is writable", INFO, detail=path)
        except PermissionError as exc:
            self._say("TranscodedWallpaper write denied: %s" % one_line(exc, 160), ERROR, detail=path)
        except Exception as exc:
            self._say("TranscodedWallpaper write test: %s" % one_line(exc, 160), WARN, detail=path)

    def _acl(self):
        self._say("I: ACL of Control Panel Desktop")
        code, out = run_text(["icacls", "HKCU\\Control Panel\\Desktop"], 20)
        if code is None:
            self._say("icacls failed: %s" % out, WARN)
            return
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            level = ERROR if "DENY" in line.upper() else INFO
            self._say("icacls: " + line, level)

    def _services(self):
        self._say("J: services")
        for svc in PROBE_SERVICES:
            code, out = run_text(["sc", "query", svc], 10)
            if code is None:
                self._say("sc query %s failed: %s" % (svc, out), WARN)
                continue
            state = ""
            for line in out.splitlines():
                if "STATE" in line:
                    state = line.strip()
                    break
            if "RUNNING" in state:
                self._say("%s %s" % (svc, state))
            elif "STOPPED" in state:
                self._say("%s %s" % (svc, state), WARN)
            else:
                self._say("%s %s" % (svc, state or "state unknown"), WARN)

    def _explorer_hints(self):
        self._say("K: Explorer policy hints")
        value = reg_read_value(hive_handle("HKCU"),
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                               "ForceClassicControlPanel")
        if value is not None:
            self._say("ForceClassicControlPanel = %s" % value)
        value = reg_read_value(hive_handle("HKLM"),
                               "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoActiveDesktop")
        if value is not None:
            self._say("NoActiveDesktop = %s" % value)
        value = reg_read_value(hive_handle("HKCU"),
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                               "NoSaveSettings")
        if value is not None:
            self._say("NoSaveSettings = %s" % value, CHANGE)

    def _shell_folders(self):
        self._say("L: user shell folders")
        profile = (os.environ.get("USERPROFILE") or "").rstrip("\\").lower()
        seen = 0
        for tag in ("Shell Folders", "User Shell Folders"):
            path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" + tag
            for name in PROBE_SHELL_FOLDERS:
                value = reg_read_value(hive_handle("HKCU"), path, name)
                if value is None:
                    continue
                seen += 1
                full = os.path.expandvars(value)
                detail = "%s\\%s\nValue: %s\nExpanded: %s" % (path, name, value, full)
                if profile and not full.lower().startswith(profile):
                    self._say("%s [%s] is outside the user profile: %s" % (tag, name, full), WARN, detail=detail)
                else:
                    self._say("%s [%s] = %s" % (tag, name, full), INFO, detail=detail)
        if not seen:
            self._say("no shell folder values could be read", WARN)


TRACE_PROVIDER_LINE = "{%s} 0xffffffffffffffff 5"


class TraceToolSource(Source):
    name = SRC_TRACE
    logman_session = "BastardTrace"

    def start(self):
        self.mode = ""
        self.etl = ""
        self.started_ok = False
        if not IS_WIN:
            self.status("off", "Windows only")
            return
        if not self.session.admin:
            self.status("off", "needs administrator")
            self.note("logman and WPR captures need administrator", WARN)
            return
        self.status("starting", "launching")
        self.spawn(self._run, "capture")

    def _run(self):
        os.makedirs(TRACE_DIR, exist_ok=True)
        if self._start_logman() or self._start_wpr():
            self.started_ok = True
            self.status("running", "%s capturing" % self.mode)
            self.note("%s is capturing to %s" % (self.mode, self.etl), INFO)
        else:
            self.status("off", "no trace tool started")
            self.note("neither logman nor WPR could start a capture", WARN)
            return
        while not self.stopping():
            self.wait(1.0)

    def _start_logman(self):
        self.etl = os.path.join(TRACE_DIR, "Bastard_logman_%s.etl" % self.session.stamp_text)
        provider_file = os.path.join(TRACE_DIR, "Bastard_providers_%s.txt" % self.session.stamp_text)
        try:
            with open(provider_file, "w", encoding="utf-8") as handle:
                for _name, guid, _kernel in ETW_RAW_PROVIDERS:
                    handle.write(TRACE_PROVIDER_LINE % guid.strip("{}") + "\n")
        except Exception as exc:
            self.note("logman provider file failed: %s" % one_line(exc, 160), WARN)
            return False
        run_text(["logman", "stop", self.logman_session, "-ets"], 20)
        code, out = run_text(["logman", "create", "trace", self.logman_session, "-ow", "-o", self.etl, "-pf",
                              provider_file, "-nb", "16", "16", "-bs", "1024", "-ets"], 30)
        if code != 0:
            self.note("logman create did not work: %s" % one_line(out, 200), INFO)
            return False
        self.mode = "logman"
        return True

    def _start_wpr(self):
        self.etl = os.path.join(TRACE_DIR, "Bastard_wpr_%s.etl" % self.session.stamp_text)
        code, out = run_text(["wpr", "-start", "FileIO", "-start", "Registry", "-filemode"], 40)
        if code != 0:
            self.note("WPR start did not work: %s" % one_line(out, 200), INFO)
            return False
        self.mode = "WPR"
        return True

    def _stop_capture(self):
        if self.mode == "logman":
            run_text(["logman", "stop", self.logman_session, "-ets"], 40)
        elif self.mode == "WPR":
            run_text(["wpr", "-stop", self.etl], 90)

    def finish(self):
        if not self.started_ok:
            return
        self.status("finishing", "stopping %s" % self.mode)
        self._stop_capture()
        if self.session.abort_event.is_set():
            return
        if not self.etl or not os.path.isfile(self.etl):
            self.status("failed", "no capture file")
            self.note("%s wrote no capture file" % self.mode, WARN)
            return
        csv_path = os.path.splitext(self.etl)[0] + ".csv"
        self.status("finishing", "decoding with tracerpt")
        code, out = run_text(["tracerpt", self.etl, "-of", "CSV", "-o", csv_path, "-y"], 180)
        if code != 0 or not os.path.isfile(csv_path):
            self.status("failed", "tracerpt failed")
            self.note("tracerpt could not decode the capture: %s" % one_line(out, 200), WARN,
                      detail="Capture file: " + self.etl)
            return
        self._publish(csv_path)

    def _publish(self, csv_path):
        listed = 0
        total = 0
        try:
            for row in procmon_csv_rows(csv_path):
                total += 1
                line = " | ".join("%s=%s" % (k, v) for k, v in row.items() if v and str(v).strip())
                low = line.lower()
                denied = "denied" in low or "0x8007" in low
                listed += 1
                if listed > PROCMON_ROW_LIMIT:
                    break
                self.emit(KIND_ETW, one_line("%s: %s" % (self.mode, line), 600),
                          ERROR if denied else INFO, detail=one_line(line, 2000))
        except Exception as exc:
            self.note("the %s capture could not be read: %s" % (self.mode, one_line(exc, 160)), WARN)
            return
        self.note("%s listed %d of %s" % (self.mode, listed, plural(total, "row")), INFO,
                  "Capture file: %s" % self.etl)
        self.status("done", "%d listed" % listed)

SOURCE_TYPES = (RegistrySource, FilesSource, ProcessSource, WindowsSource, EtwRawSource, WmiSource, EventLogSource,
                WallpaperSource, ProbeSource, ProcMonSource, TraceToolSource)
SOURCE_NAMES = [kind.name for kind in SOURCE_TYPES]


class Session:
    def __init__(self, hub, options):
        self.hub = hub
        self.options = options
        self.stop_event = threading.Event()
        self.abort_event = threading.Event()
        self.finished = threading.Event()
        self.started = time.time()
        self.stamp_text = datetime.fromtimestamp(self.started).strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(PROGRAM_DIR, "Bastard_%s.log" % self.stamp_text)
        self.pml_path = ""
        self.admin = is_admin()
        self.devices = DeviceMap()
        self.user_sid = current_user_sid()
        self.markers = []
        self.summarized = set()
        self.marker_lock = threading.Lock()
        self.stopped_at = None
        self.writer = None
        self.starter = None
        self.running = False
        self.sources = [kind(self) for kind in SOURCE_TYPES]

    def header(self):
        return [
            "Bastard %s trace log" % VERSION,
            "Started: %s" % stamp(self.started),
            "System: %s" % platform.platform(),
            "Administrator: %s" % ("yes" if self.admin else "no"),
            "Log file: %s" % self.log_path,
            "",
            "%-23s  %-10s %-8s %-8s %-30s %s" % ("Time", "Source", "Kind", "Level", "Process", "Event"),
        ]

    def begin(self):
        self.starter = threading.Thread(target=self._start, name="trace start", daemon=True)
        self.starter.start()

    def _start(self):
        rules = self.hub.exclusions
        self.writer = LogWriter(self.log_path, self.header(),
                                rules.log_bytes() if rules is not None else 0)
        written = self.writer.start()
        self.hub.writer = self.writer
        self.hub.emit(SRC_SYSTEM, KIND_SYS, "Trace started", INFO, detail="\n".join(self.header()[:5]),
                      ts=self.started)
        if not written:
            self.hub.emit(SRC_SYSTEM, KIND_SYS, "The trace log could not be written: %s" % one_line(self.writer.error, 200),
                          ERROR, detail=self.log_path)
        if IS_WIN and not self.admin:
            self.hub.emit(SRC_SYSTEM, KIND_SYS, "Not running as administrator, so ProcMon and short-lived processes are off",
                          WARN)
        for source in self.sources:
            if self.stop_event.is_set():
                break
            try:
                source.start()
            except Exception as exc:
                record_internal_error(traceback.format_exc())
                source.status("failed", one_line(exc, 60))
                source.note("could not start: %s" % one_line(exc, 200), ERROR, traceback.format_exc())
        self.running = not self.stop_event.is_set()

    def request_stop(self):
        if self.stop_event.is_set():
            return
        self.stopped_at = time.time()
        self.stop_event.set()

    def claim_marker(self, number):
        with self.marker_lock:
            if number in self.summarized:
                return False
            self.summarized.add(number)
            return True

    def finish(self):
        try:
            abort = self.abort_event.is_set()
            if self.starter is not None:
                self.starter.join(timeout=10.0 if abort else 60.0)
            for source in self.sources:
                try:
                    source.stop()
                except Exception:
                    LOG.exception("%s did not stop cleanly", source.name)
            for source in self.sources:
                source.join(2.0 if self.abort_event.is_set() else 10.0)
            for source in self.sources:
                try:
                    source.finish()
                except Exception as exc:
                    record_internal_error(traceback.format_exc())
                    source.status("failed", one_line(exc, 60))
                    source.note("could not finish: %s" % one_line(exc, 200), ERROR, traceback.format_exc())
            if self.writer is not None and not self.abort_event.is_set():
                events = list(self.writer.events)
                for number, start in list(self.markers):
                    if self.claim_marker(number):
                        text, level, detail = marker_summary(number, start, events)
                        self.hub.emit(SRC_SYSTEM, KIND_MARK, text, level, detail=detail, ts=start + MARKER_WINDOW)
            elapsed = (self.stopped_at or time.time()) - self.started
            self.hub.emit(SRC_SYSTEM, KIND_SYS, "Trace stopped after %s" % duration_text(elapsed), INFO,
                          detail="Log file: " + self.log_path)
            status, counts = self.hub.snapshot()
            for name in SOURCE_NAMES:
                state, note = status.get(name, ("idle", ""))
                if state in ("running", "starting", "finishing", "warn"):
                    self.hub.set_status(name, "idle", "stopped")
            footer = ["Summary", "Length: %s" % duration_text(elapsed)]
            for name in [SRC_SYSTEM] + SOURCE_NAMES:
                footer.append("%s: %s" % (name, plural(counts.get(name, 0), "event")))
            if self.pml_path:
                footer.append("ProcMon capture: " + self.pml_path)
            footer.append("Log file: " + self.log_path)
            writer, self.hub.writer = self.writer, None
            if writer is not None:
                writer.close(footer, not self.abort_event.is_set())
        except Exception:
            record_internal_error(traceback.format_exc())
        finally:
            self.hub.writer = None
            self.running = False
            self.finished.set()


class Theme:
    BG = "#181825"
    PANEL = "#1e1e2e"
    PANEL2 = "#252535"
    PANEL3 = "#2a2a3c"
    BORDER = "#313244"
    FG = "#cdd6f4"
    DIM = "#9399b2"
    MUTE = "#585b70"
    ACCENT = "#89b4fa"
    ACCENT2 = "#74a0e8"
    GREEN = "#a6e3a1"
    YELLOW = "#f9e2af"
    ORANGE = "#fab387"
    RED = "#f38ba8"
    PURPLE = "#cba6f7"
    SELECT = "#45475a"
    SCROLL = "#585b70"
    SCROLL_HOVER = "#7f849c"


STATE_COLORS = {"running": Theme.GREEN, "done": Theme.GREEN, "starting": Theme.YELLOW,
                "finishing": Theme.YELLOW, "warn": Theme.YELLOW, "failed": Theme.RED, "off": Theme.MUTE,
                "idle": Theme.MUTE}
STATE_WORDS = {"running": "running", "done": "done", "starting": "starting", "finishing": "finishing",
               "warn": "limited", "failed": "failed", "off": "off", "idle": "idle"}
LEVEL_COLORS = {INFO: Theme.FG, CHANGE: Theme.YELLOW, WARN: Theme.ORANGE, ERROR: Theme.RED, MARK: Theme.PURPLE}
SHOW_CHOICES = ("All events", "Changes and problems", "Problems only")
CHIP_SOURCES = (SRC_REG, SRC_FILES, SRC_PROC, SRC_WIN, SRC_LOG, SRC_PM, SRC_WALL, SRC_SYSTEM)
CHIP_KINDS = (KIND_REG, KIND_FILE, KIND_PROC, KIND_WIN, KIND_NET, KIND_DESK, KIND_LOG, KIND_ETW, KIND_PROBE,
              KIND_SYS)
DETAIL_HINT = ("Start (F5) begins a trace. Do what you want to watch, press Marker (F8) at the moment you try it, "
               "then Stop (Shift+F5).\n\nSelect an event to see its details here.")


def style_set(style, name, **options):
    try:
        style.configure(name, **options)
    except tk.TclError:
        for key, value in options.items():
            try:
                style.configure(name, **{key: value})
            except tk.TclError:
                pass


def style_map(style, name, **options):
    for key, value in options.items():
        try:
            style.map(name, **{key: value})
        except tk.TclError:
            pass


def setup_style(root):
    try:
        scale = max(1.0, float(root.winfo_fpixels("1i")) / 96.0)
    except tk.TclError:
        scale = 1.0
    fonts = (("TkDefaultFont", "Segoe UI", 9), ("TkTextFont", "Segoe UI", 9), ("TkMenuFont", "Segoe UI", 9),
             ("TkHeadingFont", "Segoe UI Semibold", 9), ("TkFixedFont", "Consolas", 9))
    for name, family, size in fonts:
        try:
            tkfont.nametofont(name).configure(family=family, size=size)
        except tk.TclError:
            pass
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    try:
        row_height = tkfont.Font(root, family="Consolas", size=9).metrics("linespace") + int(7 * scale)
    except tk.TclError:
        row_height = int(22 * scale)
    style_set(style, ".", background=Theme.BG, foreground=Theme.FG, fieldbackground=Theme.PANEL2,
              bordercolor=Theme.BORDER, lightcolor=Theme.BORDER, darkcolor=Theme.BORDER, troughcolor=Theme.PANEL2,
              focuscolor=Theme.ACCENT, selectbackground=Theme.SELECT, selectforeground=Theme.FG)
    style_set(style, "TButton", background=Theme.PANEL2, foreground=Theme.FG, borderwidth=0, focuscolor=Theme.PANEL2,
              padding=(int(12 * scale), int(5 * scale)), font=("Segoe UI", 9))
    style_map(style, "TButton", background=[("disabled", Theme.PANEL2), ("pressed", Theme.SELECT),
                                            ("active", Theme.SELECT)], foreground=[("disabled", Theme.MUTE)])
    for name, color, hover in (("Accent.TButton", Theme.ACCENT, Theme.ACCENT2), ("Danger.TButton", Theme.RED, "#e07a90"),
                               ("Warn.TButton", Theme.YELLOW, "#d8bf8a")):
        style_set(style, name, background=color, foreground=Theme.PANEL, borderwidth=0, focuscolor=color,
                  padding=(int(16 * scale), int(5 * scale)), font=("Segoe UI Semibold", 9))
        style_map(style, name, background=[("disabled", Theme.PANEL3), ("pressed", hover), ("active", hover)],
                  foreground=[("disabled", Theme.MUTE)])
    style_set(style, "Treeview", background=Theme.PANEL, foreground=Theme.FG, fieldbackground=Theme.PANEL,
              borderwidth=0, rowheight=row_height, font=("Consolas", 9))
    style_map(style, "Treeview", background=[("selected", Theme.SELECT)], foreground=[("selected", Theme.FG)])
    style_set(style, "Treeview.Heading", background=Theme.PANEL2, foreground=Theme.DIM, borderwidth=0, relief="flat",
              padding=(int(6 * scale), int(5 * scale)), font=("Segoe UI Semibold", 8))
    style_map(style, "Treeview.Heading", background=[("active", Theme.PANEL3)], foreground=[("active", Theme.FG)])
    for name in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
        style_set(style, name, background=Theme.SCROLL, troughcolor=Theme.PANEL2, bordercolor=Theme.PANEL,
                  arrowcolor=Theme.FG, gripcount=0, relief="flat", borderwidth=0, arrowsize=int(13 * scale))
        style_map(style, name, background=[("pressed", Theme.SCROLL_HOVER), ("active", Theme.SCROLL_HOVER)])
    style_set(style, "TCombobox", fieldbackground=Theme.PANEL2, background=Theme.PANEL2, foreground=Theme.FG,
              arrowcolor=Theme.FG, bordercolor=Theme.BORDER, padding=int(3 * scale))
    style_map(style, "TCombobox", fieldbackground=[("readonly", Theme.PANEL2)], foreground=[("readonly", Theme.FG)],
              selectbackground=[("readonly", Theme.PANEL2)], selectforeground=[("readonly", Theme.FG)])
    style_set(style, "TPanedwindow", background=Theme.BG)
    style_set(style, "Sash", sashthickness=int(6 * scale), background=Theme.BORDER)
    root.option_add("*TCombobox*Listbox.background", Theme.PANEL2)
    root.option_add("*TCombobox*Listbox.foreground", Theme.FG)
    root.option_add("*TCombobox*Listbox.selectBackground", Theme.SELECT)
    root.option_add("*TCombobox*Listbox.selectForeground", Theme.FG)
    return scale


def screen_box(root):
    if IS_WIN:
        try:
            metrics = ctypes.windll.user32.GetSystemMetrics
            return metrics(76), metrics(77), metrics(78), metrics(79)
        except Exception:
            pass
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


GEOMETRY_RE = re.compile(r"^(\d+)x(\d+)([+-]-?\d+)([+-]-?\d+)$")


def geometry_fits(root, geometry):
    match = GEOMETRY_RE.match(geometry or "")
    if not match:
        return False
    width, height, x, y = (int(match.group(i)) for i in range(1, 5))
    left, top, span_x, span_y = screen_box(root)
    if width < 400 or height < 300:
        return False
    return left - 50 <= x <= left + span_x - 150 and top - 20 <= y <= top + span_y - 100


def write_export(path, kind, events):
    if kind == "csv":
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Time", "Source", "Kind", "Level", "Process", "PID", "Event", "Detail"])
            for ev in events:
                writer.writerow([stamp(ev.ts), ev.source, ev.kind, LEVEL_LABELS.get(ev.level, ev.level), ev.proc,
                                 ev.pid or "", ev.text, ev.detail])
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"bastard": VERSION, "saved": stamp(time.time()), "events": [ev.to_dict() for ev in events]},
                      fh, indent=1, ensure_ascii=False)


class Led(tk.Canvas):
    def __init__(self, parent, size, bg):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self.dot = self.create_oval(1, 1, size - 1, size - 1, fill=Theme.MUTE, outline="")
        self.color = Theme.MUTE

    def set(self, color):
        if color != self.color:
            self.color = color
            self.itemconfigure(self.dot, fill=color)


class SourceRow(tk.Frame):
    def __init__(self, parent, name, scale, fonts):
        super().__init__(parent, bg=Theme.PANEL)
        top = tk.Frame(self, bg=Theme.PANEL)
        top.pack(fill="x", pady=(int(5 * scale), 0))
        self.led = Led(top, max(8, int(10 * scale)), Theme.PANEL)
        self.led.pack(side="left", padx=(int(12 * scale), int(8 * scale)))
        tk.Label(top, text=name, bg=Theme.PANEL, fg=Theme.FG, font=fonts["ui"], anchor="w").pack(side="left")
        self.count = tk.Label(top, text="", bg=Theme.PANEL, fg=Theme.DIM, font=fonts["small"])
        self.count.pack(side="right", padx=int(12 * scale))
        self.info = tk.Label(self, text="idle", bg=Theme.PANEL, fg=Theme.DIM, font=fonts["small"], anchor="w")
        self.info.pack(fill="x", padx=(int(30 * scale), int(8 * scale)), pady=(0, int(3 * scale)))
        self.last = None

    def show(self, state, note, count):
        if (state, note, count) == self.last:
            return
        self.last = (state, note, count)
        self.led.set(STATE_COLORS.get(state, Theme.MUTE))
        self.count.configure(text=str(count) if count else "")
        self.info.configure(text=shorten(note or STATE_WORDS.get(state, state), 36))


class Chip(tk.Label):
    def __init__(self, parent, text, on, command, font):
        super().__init__(parent, text=text, padx=8, pady=2, font=font, cursor="hand2", bd=0)
        self.on = on
        self.command = command
        self.bind("<Button-1>", self._toggle)
        self._paint()

    def _toggle(self, _event=None):
        self.on = not self.on
        self._paint()
        self.command()

    def _paint(self):
        if self.on:
            self.configure(bg=Theme.ACCENT, fg=Theme.PANEL)
        else:
            self.configure(bg=Theme.PANEL2, fg=Theme.DIM)


def ask_admin(root, scale):
    window = tk.Toplevel(root)
    window.title("Bastard")
    window.configure(bg=Theme.PANEL)
    window.resizable(False, False)
    try:
        window.attributes("-topmost", True)
    except tk.TclError:
        pass
    choice = {"value": "continue"}

    def choose(value):
        choice["value"] = value
        window.destroy()

    text = ("Bastard is not running as administrator.\n\nProcMon captures and short-lived processes need administrator "
            "rights. Everything else works without them.")
    tk.Label(window, text=text, justify="left", wraplength=int(420 * scale), bg=Theme.PANEL, fg=Theme.FG,
             font=("Segoe UI", 10)).pack(padx=int(24 * scale), pady=(int(20 * scale), int(14 * scale)))
    buttons = tk.Frame(window, bg=Theme.PANEL)
    buttons.pack(fill="x", padx=int(24 * scale), pady=(0, int(20 * scale)))
    ttk.Button(buttons, text="Restart as administrator", style="Accent.TButton",
               command=lambda: choose("admin")).pack(side="left")
    ttk.Button(buttons, text="Continue", command=lambda: choose("continue")).pack(side="left", padx=int(8 * scale))
    ttk.Button(buttons, text="Exit", command=lambda: choose("exit")).pack(side="right")
    window.protocol("WM_DELETE_WINDOW", lambda: choose("exit"))
    window.update_idletasks()
    width, height = window.winfo_reqwidth(), window.winfo_reqheight()
    x = max(0, (window.winfo_screenwidth() - width) // 2)
    y = max(0, (window.winfo_screenheight() - height) // 3)
    window.geometry("+%d+%d" % (x, y))
    window.lift()
    window.focus_force()
    window.wait_window()
    return choice["value"]


class App:
    def __init__(self, root, options, scale):
        self.root = root
        self.options = options
        self.scale = scale
        self.rules = load_exclusions()
        if not os.path.isfile(EXCLUSIONS_PATH):
            save_exclusions(self.rules)
        self.hub = Hub(self.rules)
        self.hub.reset(SOURCE_NAMES)
        self.store = Store()
        self.session = None
        self.finisher = None
        self.settings = load_settings()
        self.closing = False
        self.close_deadline = 0.0
        self.exit_code = 0
        self.ui_state = None
        self.rebuild_job = None
        self.rebuild_due = 0.0
        self.search_job = None
        self.match_count = 0
        self.view_count = 0
        self.marker_count = 0
        self.flash_text = ""
        self.flash_until = 0.0
        self.terms = []
        self.selftest = None
        self.admin = is_admin()
        saved_sources = self.settings.get("sources") if isinstance(self.settings.get("sources"), dict) else {}
        saved_kinds = self.settings.get("kinds") if isinstance(self.settings.get("kinds"), dict) else {}
        self.saved_sources = {name: bool(saved_sources.get(name, True)) for name in CHIP_SOURCES}
        self.saved_kinds = {name: bool(saved_kinds.get(name, True)) for name in CHIP_KINDS}
        show = as_int(self.settings.get("show"), 0)
        self.show_index = show if show in (0, 1, 2) else 0
        self.fonts = {"ui": ("Segoe UI", 9), "bold": ("Segoe UI Semibold", 9), "small": ("Segoe UI", 8),
                      "title": ("Segoe UI Semibold", 11), "mono": ("Consolas", 9), "mono_bold": ("Consolas", 9, "bold")}
        self._build()
        self._bind_keys()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = self._tk_error
        root.after(100, self._tick)
        root.after(300, self._refresh)
        if options.get("selftest"):
            self.selftest = {"ready": False, "marked": False, "done": False, "t0": 0.0}
            root.after(800, self._selftest_begin)

    def px(self, value):
        return int(value * self.scale)

    def _build(self):
        root = self.root
        root.title("Bastard %s%s" % (VERSION, " (administrator)" if self.admin else ""))
        root.configure(bg=Theme.BG)
        root.minsize(self.px(980), self.px(560))
        geometry = self.settings.get("geometry")
        if isinstance(geometry, str) and geometry_fits(root, geometry):
            root.geometry(geometry)
        else:
            width = min(self.px(1440), int(root.winfo_screenwidth() * 0.9))
            height = min(self.px(880), int(root.winfo_screenheight() * 0.85))
            root.geometry("%dx%d+%d+%d" % (width, height, max(0, (root.winfo_screenwidth() - width) // 2),
                                           max(0, (root.winfo_screenheight() - height) // 3)))
        if self.settings.get("zoomed") is True:
            try:
                root.state("zoomed")
            except tk.TclError:
                pass

        bar = tk.Frame(root, bg=Theme.PANEL, padx=self.px(10), pady=self.px(8))
        bar.pack(side="top", fill="x")
        tk.Label(bar, text="BASTARD", bg=Theme.PANEL, fg=Theme.ACCENT, font=self.fonts["title"]).pack(side="left")
        tk.Label(bar, text=VERSION, bg=Theme.PANEL, fg=Theme.DIM, font=self.fonts["small"]).pack(
            side="left", padx=(self.px(4), self.px(16)))
        self.btn_start = ttk.Button(bar, text="Start", style="Accent.TButton", command=self.start_trace)
        self.btn_start.pack(side="left", padx=self.px(2))
        self.btn_stop = ttk.Button(bar, text="Stop", style="Danger.TButton", command=self.stop_trace)
        self.btn_stop.pack(side="left", padx=self.px(2))
        self.btn_marker = ttk.Button(bar, text="Marker", style="Warn.TButton", command=self.add_marker)
        self.btn_marker.pack(side="left", padx=(self.px(10), self.px(2)))
        self.timer = tk.Label(bar, text="", bg=Theme.PANEL, fg=Theme.GREEN, font=self.fonts["mono_bold"])
        self.timer.pack(side="left", padx=self.px(14))
        self.btn_options = ttk.Button(bar, text="Options", command=self.edit_options)
        self.btn_options.pack(side="right", padx=self.px(2))
        self.btn_filter = ttk.Button(bar, text="Filter", command=self.edit_filter)
        self.btn_filter.pack(side="right", padx=self.px(2))
        admin_text = "administrator" if self.admin else ("not administrator" if IS_WIN else "")
        tk.Label(bar, text=admin_text, bg=Theme.PANEL, fg=Theme.GREEN if self.admin else Theme.ORANGE,
                 font=self.fonts["small"]).pack(side="right", padx=self.px(12))

        footer = tk.Frame(root, bg=Theme.PANEL, height=self.px(26))
        footer.pack(side="bottom", fill="x")
        footer.pack_propagate(False)
        self.status_label = tk.Label(footer, text="Ready", bg=Theme.PANEL, fg=Theme.DIM, anchor="w",
                                     font=self.fonts["small"])
        self.status_label.pack(side="left", padx=self.px(12))
        self.log_label = tk.Label(footer, text="", bg=Theme.PANEL, fg=Theme.MUTE, anchor="e", font=self.fonts["small"])
        self.log_label.pack(side="right", padx=self.px(12))

        body = tk.Frame(root, bg=Theme.BG)
        body.pack(side="top", fill="both", expand=True)
        left = tk.Frame(body, bg=Theme.PANEL, width=self.px(250))
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="SOURCES", bg=Theme.PANEL, fg=Theme.DIM, font=("Segoe UI Semibold", 8), anchor="w").pack(
            side="top", fill="x", padx=self.px(12), pady=(self.px(12), self.px(4)))
        self.rows = {}
        for name in SOURCE_NAMES:
            row = SourceRow(left, name, self.scale, self.fonts)
            row.pack(side="top", fill="x")
            self.rows[name] = row
        legend = tk.Frame(left, bg=Theme.PANEL)
        legend.pack(side="bottom", fill="x", padx=self.px(12), pady=self.px(10))
        for color, text in ((Theme.GREEN, "running"), (Theme.YELLOW, "starting, busy or limited"),
                            (Theme.RED, "failed"), (Theme.MUTE, "off or idle")):
            line = tk.Frame(legend, bg=Theme.PANEL)
            line.pack(side="top", anchor="w", pady=1)
            led = Led(line, max(7, self.px(8)), Theme.PANEL)
            led.pack(side="left")
            led.set(color)
            tk.Label(line, text="  " + text, bg=Theme.PANEL, fg=Theme.DIM, font=self.fonts["small"]).pack(side="left")

        right = tk.Frame(body, bg=Theme.BG)
        right.pack(side="left", fill="both", expand=True)
        filters = tk.Frame(right, bg=Theme.BG, padx=self.px(10), pady=self.px(8))
        filters.pack(side="top", fill="x")
        tk.Label(filters, text="SOURCE", bg=Theme.BG, fg=Theme.DIM, font=("Segoe UI Semibold", 7)).grid(
            row=0, column=0, sticky="w", padx=(0, self.px(6)))
        holder = tk.Frame(filters, bg=Theme.BG)
        holder.grid(row=0, column=1, sticky="w")
        self.source_chips = {}
        for name in CHIP_SOURCES:
            chip = Chip(holder, name, self.saved_sources[name], self._filters_changed, self.fonts["small"])
            chip.pack(side="left", padx=1)
            self.source_chips[name] = chip
        tk.Label(filters, text="KIND", bg=Theme.BG, fg=Theme.DIM, font=("Segoe UI Semibold", 7)).grid(
            row=1, column=0, sticky="w", padx=(0, self.px(6)), pady=(self.px(6), 0))
        holder = tk.Frame(filters, bg=Theme.BG)
        holder.grid(row=1, column=1, sticky="w", pady=(self.px(6), 0))
        self.kind_chips = {}
        for name in CHIP_KINDS:
            chip = Chip(holder, name, self.saved_kinds[name], self._filters_changed, self.fonts["small"])
            chip.pack(side="left", padx=1)
            self.kind_chips[name] = chip
        side = tk.Frame(filters, bg=Theme.BG)
        side.grid(row=0, column=2, rowspan=2, sticky="e", padx=(self.px(12), 0))
        tk.Label(side, text="Show", bg=Theme.BG, fg=Theme.DIM, font=self.fonts["ui"]).grid(row=0, column=0, sticky="e")
        self.show_box = ttk.Combobox(side, values=SHOW_CHOICES, state="readonly", width=22, font=self.fonts["ui"])
        self.show_box.current(self.show_index)
        self.show_box.grid(row=0, column=1, sticky="w", padx=(self.px(6), 0))
        self.show_box.bind("<<ComboboxSelected>>", lambda _e: self._filters_changed())
        tk.Label(side, text="Search", bg=Theme.BG, fg=Theme.DIM, font=self.fonts["ui"]).grid(
            row=1, column=0, sticky="e", pady=(self.px(6), 0))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(side, textvariable=self.search_var, width=26, bg=Theme.PANEL2, fg=Theme.FG,
                                     insertbackground=Theme.FG, bd=0, highlightthickness=1,
                                     highlightbackground=Theme.BORDER, highlightcolor=Theme.ACCENT,
                                     font=self.fonts["ui"])
        self.search_entry.grid(row=1, column=1, sticky="we", padx=(self.px(6), 0), pady=(self.px(6), 0), ipady=2)
        self.search_entry.bind("<KeyRelease>", self._search_typed)
        self.search_entry.bind("<Escape>", self._search_clear)
        filters.columnconfigure(1, weight=1)

        self.paned = ttk.PanedWindow(right, orient="vertical")
        self.paned.pack(side="top", fill="both", expand=True, padx=self.px(10), pady=(0, self.px(10)))
        upper = tk.Frame(self.paned, bg=Theme.BG)
        columns = ("time", "source", "kind", "process", "pid", "event")
        self.tree = ttk.Treeview(upper, columns=columns, show="headings", selectmode="extended")
        widths = {"time": 100, "source": 92, "kind": 74, "process": 170, "pid": 64, "event": 1100}
        titles = {"time": "Time", "source": "Source", "kind": "Kind", "process": "Process", "pid": "PID",
                  "event": "Event"}
        for column in columns:
            self.tree.heading(column, text=titles[column], anchor="w")
            self.tree.column(column, width=self.px(widths[column]), minwidth=self.px(40),
                             anchor="e" if column == "pid" else "w", stretch=column == "event")
        scroll_y = ttk.Scrollbar(upper, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(upper, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        for level, color in LEVEL_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        self.tree.tag_configure(MARK, foreground=Theme.PURPLE, font=self.fonts["mono_bold"])
        self.menu = tk.Menu(self.tree, tearoff=0, bg=Theme.PANEL, fg=Theme.FG,
                            activebackground=Theme.ACCENT, activeforeground=Theme.PANEL, bd=0)
        self.menu.add_command(label="Leave this match out", command=self.exclude_selected)
        self.menu.add_command(label="Copy", command=self.copy_selection)
        self.menu_row = ""
        self.tree.bind("<Button-3>", self._popup)
        self.tree.bind("<<TreeviewSelect>>", self._selected)
        self.tree.bind("<Control-c>", self.copy_selection)
        self.tree.bind("<Control-C>", self.copy_selection)
        self.tree.bind("<Escape>", self._clear_selection)
        lower = tk.Frame(self.paned, bg=Theme.BG)
        head = tk.Frame(lower, bg=Theme.BG)
        head.pack(side="top", fill="x", pady=(self.px(6), self.px(4)))
        tk.Label(head, text="DETAILS", bg=Theme.BG, fg=Theme.ACCENT, font=("Segoe UI Semibold", 8)).pack(side="left")
        ttk.Button(head, text="Copy", command=self.copy_selection).pack(side="right")
        holder = tk.Frame(lower, bg=Theme.PANEL)
        holder.pack(side="top", fill="both", expand=True)
        self.detail = tk.Text(holder, bg=Theme.PANEL, fg=Theme.FG, font=self.fonts["mono"], wrap="word", bd=0,
                              padx=self.px(10), pady=self.px(8), height=8, insertbackground=Theme.FG,
                              selectbackground=Theme.SELECT, highlightthickness=0)
        detail_scroll = ttk.Scrollbar(holder, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side="right", fill="y")
        self.detail.pack(side="left", fill="both", expand=True)
        self.paned.add(upper, weight=4)
        self.paned.add(lower, weight=1)
        self._show_detail(DETAIL_HINT)
        sash = as_int(self.settings.get("sash"))
        if sash and sash > self.px(120):
            root.after(150, lambda: self._restore_sash(sash))
        self._apply_state("idle")

    def _restore_sash(self, value):
        try:
            self.paned.sashpos(0, value)
        except tk.TclError:
            pass

    def _bind_keys(self):
        root = self.root
        root.bind("<F5>", lambda _e: self.start_trace())
        root.bind("<Shift-F5>", lambda _e: self.stop_trace())
        root.bind("<F8>", lambda _e: self.add_marker())
        root.bind("<Control-f>", self._focus_search)
        root.bind("<Control-F>", self._focus_search)
        root.bind("<Control-s>", lambda _e: self.export("csv"))
        root.bind("<Control-S>", lambda _e: self.export("csv"))
        root.bind("<Control-j>", lambda _e: self.export("json"))
        root.bind("<Control-J>", lambda _e: self.export("json"))
        root.bind("<Control-Shift-C>", self.copy_selection)

    def _tk_error(self, kind, value, tb):
        text = "".join(traceback.format_exception(kind, value, tb))
        record_internal_error(text)
        self.exit_code = 3
        self.flash("Bastard hit an internal error. Details are in " + APP_LOG_PATH)

    def flash(self, text):
        self.flash_text = text
        self.flash_until = time.time() + 6.0
        self.status_label.configure(text=text)

    def _show_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def _match(self, ev):
        if ev.kind == KIND_MARK:
            return True
        if self.rules is not None and self.rules.blocks(ev.source, ev.level, ev.text):
            return False
        chip = self.source_chips.get(ev.source)
        if chip is not None and not chip.on:
            return False
        chip = self.kind_chips.get(ev.kind)
        if chip is not None and not chip.on:
            return False
        if self.show_index == 1 and ev.level not in (CHANGE, WARN, ERROR):
            return False
        if self.show_index == 2 and ev.level not in (WARN, ERROR):
            return False
        if self.terms:
            hay = ("%s %s %s %s %s" % (ev.text, ev.proc, ev.source, ev.kind, ev.detail)).lower()
            for term in self.terms:
                if term not in hay:
                    return False
        return True

    def _values(self, ev):
        return (clock(ev.ts), ev.source, ev.kind, ev.proc, ev.pid or "", shorten(ev.text, 600))

    def _following(self):
        if self.tree.selection():
            return False
        try:
            return self.tree.yview()[1] >= 0.999
        except tk.TclError:
            return True

    def _append(self, events):
        rows = [ev for ev in events if self._match(ev)]
        if not rows:
            return
        follow = self._following()
        for ev in rows:
            self.tree.insert("", "end", iid=str(ev.seq), values=self._values(ev), tags=(ev.level,))
        self.view_count += len(rows)
        self.match_count += len(rows)
        if self.view_count > VIEW_LIMIT + VIEW_LIMIT // 10:
            children = self.tree.get_children()
            extra = len(children) - VIEW_LIMIT
            if extra > 0:
                self.tree.delete(*children[:extra])
            self.view_count = len(children) - max(0, extra)
        if follow:
            self.tree.yview_moveto(1.0)

    def _schedule_rebuild(self, delay):
        now = time.time()
        if self.rebuild_job is not None:
            if now + delay / 1000.0 > self.rebuild_due + 2.0:
                return
            self.root.after_cancel(self.rebuild_job)
        else:
            self.rebuild_due = now
        self.rebuild_job = self.root.after(delay, self._rebuild)

    def _rebuild(self):
        self.rebuild_job = None
        selected = self.tree.selection()
        follow = self._following()
        matches = [ev for ev in self.store.events() if self._match(ev)]
        self.match_count = len(matches)
        rows = matches[-VIEW_LIMIT:]
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for ev in rows:
            self.tree.insert("", "end", iid=str(ev.seq), values=self._values(ev), tags=(ev.level,))
        self.view_count = len(rows)
        keep = [iid for iid in selected if self.tree.exists(iid)]
        if keep:
            self.tree.selection_set(keep)
            self.tree.see(keep[0])
        elif follow:
            self.tree.yview_moveto(1.0)

    def _drain(self):
        batch = []
        try:
            while len(batch) < 5000:
                batch.append(self.hub.ui.get_nowait())
        except queue.Empty:
            pass
        if batch:
            if self.store.add(batch) and self.rebuild_job is None:
                self._append(batch)
            else:
                self._schedule_rebuild(400)
        return len(batch)

    def _tick(self):
        try:
            self._drain()
            self._check_session()
        except Exception:
            self._tk_error(*sys.exc_info())
        self.root.after(100, self._tick)

    def _refresh(self):
        try:
            status, counts = self.hub.snapshot()
            for name, row in self.rows.items():
                state, note = status.get(name, ("idle", ""))
                row.show(state, note, counts.get(name, 0))
            session = self.session
            if session is not None and not session.stop_event.is_set():
                self.timer.configure(text=duration_clock(time.time() - session.started), fg=Theme.GREEN)
            elif session is not None and not session.finished.is_set():
                self.timer.configure(text="finishing", fg=Theme.YELLOW)
            if time.time() > self.flash_until:
                self.status_label.configure(text=self._status_text())
            if session is not None:
                self.log_label.configure(text="Log: " + session.log_path)
        except Exception:
            self._tk_error(*sys.exc_info())
        self.root.after(500, self._refresh)

    def _busy_note(self):
        session = self.session
        if session is None or session.finished.is_set() or not session.stop_event.is_set():
            return ""
        status, _counts = self.hub.snapshot()
        busy = sorted(name for name, value in status.items()
                      if value[0] in ("running", "starting", "finishing"))
        if not busy:
            return "finishing"
        return "finishing: %s still reading what it captured" % ", ".join(busy)

    def _status_text(self):
        busy = self._busy_note()
        total = len(self.store.items)
        if not total:
            return busy or ("Ready" if self.session is None else "Waiting for events")
        text = "%s, %d match the filters" % (plural(total, "event"), self.match_count)
        if busy:
            text = busy + ", " + text
        if self.match_count > self.view_count:
            text += ", the newest %d are listed" % self.view_count
        if self.store.dropped:
            text += ", %d more are only in the log" % self.store.dropped
        if self.rules is not None and self.rules.blocked:
            text += ", %d left out by the filter" % self.rules.blocked
        return text

    def _check_session(self):
        session = self.session
        if session is None:
            state = "idle"
        elif session.finished.is_set():
            state = "done"
        elif session.stop_event.is_set():
            state = "finishing"
        else:
            state = "running"
        if state != self.ui_state:
            self._apply_state(state)

    def _apply_state(self, state):
        self.ui_state = state
        running = state == "running"
        busy = state in ("running", "finishing")
        self.btn_start.configure(state="disabled" if busy or self.closing else "normal")
        self.btn_stop.configure(state="normal" if running and not self.closing else "disabled")
        self.btn_marker.configure(state="normal" if running and not self.closing else "disabled")
        session = self.session
        if state == "done" and session is not None:
            self.timer.configure(text=duration_clock((session.stopped_at or time.time()) - session.started),
                                 fg=Theme.DIM)
            if session.writer is not None and session.writer.error:
                self.flash("The trace log could not be written: " + one_line(session.writer.error, 160))
            else:
                self.flash("Trace saved to " + session.log_path)

    def start_trace(self):
        if self.closing or (self.session is not None and not self.session.finished.is_set()):
            return
        try:
            while True:
                self.hub.ui.get_nowait()
        except queue.Empty:
            pass
        self.store.clear()
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        self.view_count = 0
        self.match_count = 0
        self.marker_count = 0
        self._show_detail(DETAIL_HINT)
        self.hub.reset(SOURCE_NAMES)
        self.session = Session(self.hub, self.options)
        self.session.begin()
        self._check_session()

    def stop_trace(self):
        session = self.session
        if session is None or session.stop_event.is_set():
            return
        session.request_stop()
        self.finisher = threading.Thread(target=session.finish, name="trace finish", daemon=True)
        self.finisher.start()
        self._check_session()

    def add_marker(self):
        session = self.session
        if session is None or session.stop_event.is_set() or self.closing:
            return
        self.marker_count += 1
        number = self.marker_count
        moment = time.time()
        session.markers.append((number, moment))
        self.hub.emit(SRC_SYSTEM, KIND_MARK, "Marker %d" % number, MARK, ts=moment)
        self.root.after(int(MARKER_DELAY * 1000), lambda: self._marker_due(session, number, moment))

    def _marker_due(self, session, number, moment):
        if session is not self.session or not session.claim_marker(number):
            return
        self._drain()
        text, level, detail = marker_summary(number, moment, self.store.window(moment, moment + MARKER_WINDOW))
        self.hub.emit(SRC_SYSTEM, KIND_MARK, text, level, detail=detail, ts=moment + MARKER_WINDOW)

    def _filters_changed(self):
        try:
            self.show_index = max(0, self.show_box.current())
        except tk.TclError:
            self.show_index = 0
        self.terms = self.search_var.get().lower().split()
        self._schedule_rebuild(30)

    def _search_typed(self, _event=None):
        if self.search_job is not None:
            self.root.after_cancel(self.search_job)
        self.search_job = self.root.after(250, self._search_apply)

    def _search_apply(self):
        self.search_job = None
        self._filters_changed()

    def _search_clear(self, _event=None):
        self.search_var.set("")
        self._filters_changed()
        return "break"

    def _focus_search(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")
        return "break"

    def _clear_selection(self, _event=None):
        selection = self.tree.selection()
        if selection:
            self.tree.selection_remove(*selection)
        self._show_detail(DETAIL_HINT)
        return "break"

    def _selected(self, _event=None):
        events = [self.store.by_seq.get(int(iid)) for iid in self.tree.selection()]
        events = [ev for ev in events if ev is not None]
        if not events:
            return
        text = events[0].describe()
        if len(events) > 1:
            text = "%d events are selected. Copy puts all of them on the clipboard.\n\n%s" % (len(events), text)
        self._show_detail(text)

    def copy_selection(self, _event=None):
        events = [self.store.by_seq.get(int(iid)) for iid in self.tree.selection()]
        events = [ev for ev in events if ev is not None]
        if not events:
            return "break"
        self.root.clipboard_clear()
        self.root.clipboard_append("\n\n".join(ev.describe() for ev in events))
        self.flash("Copied " + plural(len(events), "event"))
        return "break"

    def export(self, kind):
        if self.closing:
            return
        events = [ev for ev in self.store.events() if self._match(ev)]
        if not events:
            messagebox.showinfo("Bastard", "There are no events to save.", parent=self.root)
            return
        name = "Bastard_%s.%s" % (datetime.now().strftime("%Y%m%d_%H%M%S"), kind)
        path = filedialog.asksaveasfilename(parent=self.root, title="Export " + kind.upper(), initialdir=DESKTOP,
                                            initialfile=name, defaultextension="." + kind,
                                            filetypes=[(kind.upper(), "*." + kind), ("All files", "*.*")])
        if not path:
            return
        try:
            write_export(path, kind, events)
            self.flash("Saved %s to %s" % (plural(len(events), "event"), path))
        except Exception as exc:
            messagebox.showerror("Bastard", "The file could not be saved:\n%s" % exc, parent=self.root)

    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        self.menu_row = row
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def exclude_selected(self):
        ev = self.store.by_seq.get(int(self.menu_row)) if self.menu_row.isdigit() else None
        if ev is None:
            return
        if ev.source == SRC_SYSTEM:
            self.flash("System events are never left out")
            return
        line = exclusion_from(ev)
        if line in self.rules.lines:
            self.flash("That rule is already in the filter")
            return
        self.rules.set_lines(list(self.rules.lines) + [line])
        self.rules.enabled = True
        error = save_exclusions(self.rules)
        self._schedule_rebuild(1)
        if error:
            self.flash("The rules could not be saved: " + one_line(error, 120))
        else:
            self.flash("Left out from now on: " + one_line(line, 150))

    def _dialog(self, title):
        window = tk.Toplevel(self.root)
        window.title("Bastard - " + title)
        window.configure(bg=Theme.PANEL)
        window.transient(self.root)
        try:
            window.geometry("+%d+%d" % (self.root.winfo_rootx() + self.px(70),
                                        self.root.winfo_rooty() + self.px(70)))
        except tk.TclError:
            pass
        return window

    def _dialog_note(self, window, text, color):
        tk.Label(window, text=text, bg=Theme.PANEL, fg=color, font=self.fonts["small"], anchor="w",
                 justify="left", wraplength=self.px(560)).pack(fill="x", padx=self.px(12))

    def edit_filter(self):
        window = self._dialog("Filter")
        self._dialog_note(window, "Events a rule catches stay out of the timeline and out of the log.", Theme.FG)
        for note in EXCLUSION_HELP:
            self._dialog_note(window, note, Theme.DIM)
        box = tk.Text(window, bg=Theme.BG, fg=Theme.FG, insertbackground=Theme.FG, font=self.fonts["mono"],
                      height=14, width=94, bd=0, highlightthickness=1, highlightbackground=Theme.PANEL2)
        box.pack(fill="both", expand=True, padx=self.px(12), pady=self.px(8))
        box.insert("1.0", "\n".join(self.rules.lines))
        state = tk.BooleanVar(value=self.rules.enabled)
        tk.Checkbutton(window, text="Use these rules", variable=state, bg=Theme.PANEL, fg=Theme.FG,
                       selectcolor=Theme.BG, activebackground=Theme.PANEL, activeforeground=Theme.FG,
                       font=self.fonts["small"]).pack(anchor="w", padx=self.px(10))
        self._dialog_note(window, "Saved in " + EXCLUSIONS_PATH, Theme.DIM)
        row = tk.Frame(window, bg=Theme.PANEL)
        row.pack(fill="x", padx=self.px(12), pady=self.px(10))

        def keep():
            self.rules.set_lines(box.get("1.0", "end").splitlines())
            self.rules.enabled = bool(state.get())
            error = save_exclusions(self.rules)
            window.destroy()
            self._schedule_rebuild(1)
            if error:
                self.flash("The rules could not be saved: " + one_line(error, 120))
            else:
                self.flash("%s saved" % plural(len(self.rules.lines), "rule"))

        def defaults():
            box.delete("1.0", "end")
            box.insert("1.0", "\n".join(DEFAULT_EXCLUSIONS))

        ttk.Button(row, text="Save", style="Accent.TButton", command=keep).pack(side="right", padx=self.px(2))
        ttk.Button(row, text="Cancel", command=window.destroy).pack(side="right", padx=self.px(2))
        ttk.Button(row, text="Back to the defaults", command=defaults).pack(side="left")
        box.focus_set()

    def edit_options(self):
        window = self._dialog("Options")
        self._dialog_note(window, "How large the trace log on disk may grow.", Theme.FG)
        self._dialog_note(window, "The trace stops writing to the log once it reaches this, and says so in "
                                  "the log and in the footer. The timeline keeps going.", Theme.DIM)
        row = tk.Frame(window, bg=Theme.PANEL)
        row.pack(fill="x", padx=self.px(12), pady=self.px(10))
        tk.Label(row, text="Log limit", bg=Theme.PANEL, fg=Theme.FG,
                 font=self.fonts["ui"]).pack(side="left", padx=(0, self.px(8)))
        value = tk.StringVar(value=str(self.rules.log_mb))
        entry = ttk.Entry(row, textvariable=value, width=8, font=self.fonts["mono"])
        entry.pack(side="left")
        tk.Label(row, text="MB", bg=Theme.PANEL, fg=Theme.DIM,
                 font=self.fonts["ui"]).pack(side="left", padx=self.px(6))
        self._dialog_note(window, "Saved in " + EXCLUSIONS_PATH, Theme.DIM)
        buttons = tk.Frame(window, bg=Theme.PANEL)
        buttons.pack(fill="x", padx=self.px(12), pady=self.px(10))

        def keep():
            try:
                size = int(value.get().strip())
            except ValueError:
                self.flash("The log limit has to be a whole number of megabytes")
                return
            self.rules.log_mb = max(1, min(size, 4096))
            error = save_exclusions(self.rules)
            window.destroy()
            if error:
                self.flash("The limit could not be saved: " + one_line(error, 120))
            else:
                self.flash("The log limit is %d MB from the next trace on" % self.rules.log_mb)

        ttk.Button(buttons, text="Save", style="Accent.TButton", command=keep).pack(side="right", padx=self.px(2))
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right", padx=self.px(2))
        entry.focus_set()

    def _save_settings(self):
        data = dict(self.settings)
        try:
            zoomed = self.root.state() == "zoomed"
            data["zoomed"] = zoomed
            if not zoomed:
                data["geometry"] = self.root.geometry()
            data["sash"] = int(self.paned.sashpos(0))
        except tk.TclError:
            pass
        data["sources"] = {name: chip.on for name, chip in self.source_chips.items()}
        data["kinds"] = {name: chip.on for name, chip in self.kind_chips.items()}
        data["show"] = self.show_index
        save_settings(data)

    def on_close(self):
        if self.closing:
            return
        self.closing = True
        self._save_settings()
        session = self.session
        if session is not None and not session.finished.is_set():
            session.abort_event.set()
            if not session.stop_event.is_set():
                session.request_stop()
                self.finisher = threading.Thread(target=session.finish, name="trace finish", daemon=True)
                self.finisher.start()
            self._apply_state("finishing")
            self.flash("Closing, the sources are being stopped")
            self.close_deadline = time.time() + 20.0
            self.root.after(200, self._close_wait)
        else:
            self.root.destroy()

    def _close_wait(self):
        session = self.session
        if session is None or session.finished.is_set() or time.time() > self.close_deadline:
            self.root.destroy()
        else:
            self.root.after(200, self._close_wait)

    def _selftest_begin(self):
        self.start_trace()
        self.selftest["t0"] = time.time()
        self.root.after(200, self._selftest_step)

    def _selftest_step(self):
        state = self.selftest
        session = self.session
        elapsed = time.time() - state["t0"]
        if not state["ready"] and session.running:
            state["ready"] = True
            with open(self.options["selftest"] + ".ready", "w", encoding="utf-8") as fh:
                json.dump({"time": time.time()}, fh)
        if state["ready"] and not state["marked"] and elapsed >= self.options["marker_at"]:
            state["marked"] = True
            self.add_marker()
        if not session.stop_event.is_set() and elapsed >= self.options["seconds"]:
            self.stop_trace()
        if session.finished.is_set():
            if not state["done"]:
                state["done"] = True
                self.root.after(1500, self._selftest_finish)
            return
        self.root.after(200, self._selftest_step)

    def _selftest_finish(self):
        try:
            self._selftest_report()
        except Exception:
            record_internal_error(traceback.format_exc())
        if INTERNAL_ERRORS:
            self.exit_code = 3
        self.on_close()

    def _selftest_report(self):
        while self._drain():
            pass
        if self.rebuild_job is not None:
            self.root.after_cancel(self.rebuild_job)
            self._rebuild()
        session = self.session
        status, counts = self.hub.snapshot()
        log_text = ""
        try:
            with open(session.log_path, "r", encoding="utf-8") as fh:
                log_text = fh.read()
        except OSError:
            pass
        times = [line[:23] for line in log_text.splitlines() if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:", line)]
        exports = {}
        for kind in ("csv", "json"):
            path = self.options["selftest"] + "." + kind
            try:
                write_export(path, kind, self.store.events())
                exports[kind] = os.path.getsize(path) > 0
            except Exception as exc:
                exports[kind] = False
                record_internal_error("export %s: %s" % (kind, exc))
        result = {
            "version": VERSION, "platform": platform.platform(), "admin": session.admin,
            "status": {name: list(value) for name, value in status.items()}, "counts": counts,
            "events": [ev.to_dict() for ev in sample_events(self.store.events(), SELFTEST_EVENTS)],
            "errors": list(INTERNAL_ERRORS),
            "log_path": session.log_path, "log_exists": bool(log_text), "log_lines": len(times),
            "log_sorted": times == sorted(times), "pml_path": session.pml_path, "exports": exports,
            "listed": len(self.tree.get_children()), "matching": self.match_count,
        }
        with open(self.options["selftest"], "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1)


def duration_clock(seconds):
    seconds = max(0, int(seconds))
    return "%02d:%02d:%02d" % (seconds // 3600, (seconds // 60) % 60, seconds % 60)


def parse_options(argv):
    options = {"selftest": "", "watch_keys": [], "watch_folders": [], "seconds": 30.0, "marker_at": 8.0}
    index = 0
    while index < len(argv):
        arg = argv[index]
        value = argv[index + 1] if index + 1 < len(argv) else ""
        if arg == "--selftest":
            options["selftest"] = os.path.abspath(value)
        elif arg == "--watch-key":
            options["watch_keys"].append(value)
        elif arg == "--watch-folder":
            options["watch_folders"].append(os.path.abspath(value))
        elif arg == "--seconds":
            options["seconds"] = float(value)
        elif arg == "--marker-at":
            options["marker_at"] = float(value)
        else:
            index += 1
            continue
        index += 2
    return options


def main(argv):
    options = parse_options(argv)
    setup_app_log()
    install_error_hooks()
    LOG.info("Bastard %s starting, administrator %s", VERSION, is_admin())
    enable_dpi_awareness()
    root = tk.Tk()
    root.withdraw()
    scale = setup_style(root)
    if IS_WIN and not is_admin() and not options["selftest"]:
        choice = ask_admin(root, scale)
        if choice == "exit":
            root.destroy()
            return 0
        if choice == "admin":
            if relaunch_as_admin():
                root.destroy()
                return 0
            messagebox.showwarning("Bastard", "Bastard could not restart as administrator, so it carries on without.")
    app = App(root, options, scale)
    root.deiconify()
    root.mainloop()
    LOG.info("Bastard closed")
    return app.exit_code


if __name__ == "__main__":
    exit_code = 1
    try:
        exit_code = main(sys.argv[1:])
    except Exception:
        record_internal_error(traceback.format_exc())
        try:
            messagebox.showerror("Bastard", "Bastard stopped because of an error. Details are in:\n" + APP_LOG_PATH)
        except Exception:
            pass
    finally:
        logging.shutdown()
    os._exit(exit_code)
