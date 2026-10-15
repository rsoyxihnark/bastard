import contextlib
import csv
import importlib
import importlib.machinery
import importlib.util
import io
import json
import os
import queue
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(os.path.dirname(HERE), "bastard.pyw")


def load():
    loader = importlib.machinery.SourceFileLoader("bastard_under_test", SOURCE)
    spec = importlib.util.spec_from_loader("bastard_under_test", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


b = load()
selftest = importlib.import_module("run_selftest") if HERE in sys.path else None
if selftest is None:
    sys.path.insert(0, HERE)
    selftest = importlib.import_module("run_selftest")
SELFTEST_WORK = "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\%sab12cd34\\watched" % selftest.WORK_PREFIX
gate = importlib.import_module("release_gate")
source_check = importlib.import_module("check_source")
notes_sync = importlib.import_module("sync_release_notes")
ROOT = os.path.dirname(HERE)


def event(ts, source="Files", kind="File", level="change", text="x", proc="", pid=None, seq=None):
    event.counter += 1
    return b.Event(ts, seq or event.counter, source, kind, level, pid, proc, text, "")


event.counter = 0


class FakeSession:
    def __init__(self, hub=None):
        self.hub = hub if hub is not None else b.Hub()
        self.markers = []
        self.stop_event = threading.Event()
        self.abort_event = threading.Event()
        self.admin = False


def drained(hub):
    out = []
    while True:
        try:
            out.append(hub.ui.get_nowait())
        except queue.Empty:
            return out


def filetime(epoch):
    return int(epoch * 10000000) + b.FILETIME_EPOCH


OTHER_PID = 4321 if os.getpid() != 4321 else 4325


class QuietProcMon(b.ProcMonSource):
    def __init__(self, hub):
        self.hub = hub
        self.session = type("S", (), {"markers": []})()
        self.pml = "x.pml"

    def status(self, state, note=""):
        pass

    def note(self, text, level=b.INFO, detail=""):
        pass


def procmon_listed(rules, rows):
    hub = b.Hub(rules)
    digest = b.ProcmonDigest(1, 1000)
    now = time.time()
    for index, (proc, operation, path, result) in enumerate(rows):
        digest.add(now + index * 0.001, proc, OTHER_PID, operation, path, result)
    QuietProcMon(hub)._publish(digest, "%d events" % len(rows))
    return drained(hub)


def etw_listed(rules, items):
    hub = b.Hub(rules)
    source = b.EtwRawSource(FakeSession(hub))
    source.own_pid = -1
    for event_id, data in items:
        source._on((event_id, data))
    return drained(hub)


class Formatting(unittest.TestCase):
    def test_dword_and_qword(self):
        self.assertEqual(b.format_reg_value("x", 4, 10), "10 (0xA)")
        self.assertEqual(b.format_reg_value("x", 11, 2 ** 40), "%d (0x%X)" % (2 ** 40, 2 ** 40))

    def test_strings(self):
        self.assertEqual(b.format_reg_value("x", 1, "C:\\a.jpg"), '"C:\\a.jpg"')
        self.assertEqual(b.format_reg_value("x", 7, ["a", "b"]), '["a", "b"]')
        self.assertTrue(b.format_reg_value("x", 1, "y" * 500).endswith('..."'))

    def test_binary(self):
        self.assertEqual(b.format_reg_value("x", 3, b""), "0 bytes")
        self.assertEqual(b.format_reg_value("x", 3, b"\x01\x02"), "2 bytes: 01 02")
        self.assertTrue(b.format_reg_value("x", 3, bytes(40)).endswith(" ..."))

    def test_transcoded_image_cache(self):
        blob = bytes(24) + "C:\\Users\\me\\Pictures\\sea.jpg".encode("utf-16-le") + bytes(64)
        self.assertEqual(b.decode_transcoded_image(blob), "C:\\Users\\me\\Pictures\\sea.jpg")
        text = b.format_reg_value("TranscodedImageCache", 3, blob)
        self.assertTrue(text.startswith('image "C:\\Users\\me\\Pictures\\sea.jpg"'), text)
        self.assertEqual(b.decode_transcoded_image(bytes(30)), "")

    def test_numbers_and_words(self):
        self.assertEqual(b.as_int("0x1F"), 31)
        self.assertEqual(b.as_int(" 12 "), 12)
        self.assertEqual(b.as_int("nope", -1), -1)
        self.assertEqual(b.exit_code_text(7), "7")
        self.assertEqual(b.exit_code_text(0xC0000005), "0xC0000005")
        self.assertEqual(b.exit_code_text(-1073741819), "0xC0000005")
        self.assertEqual(b.plural(1, "event"), "1 event")
        self.assertEqual(b.plural(3, "event"), "3 events")
        self.assertEqual(b.duration_text(5), "5 seconds")
        self.assertEqual(b.duration_text(125), "2 min 5 s")
        self.assertEqual(b.short_duration(0.44), "0.4 s")
        self.assertEqual(b.process_label("a.exe", 4), "a.exe (PID 4)")
        self.assertEqual(b.process_label("", 4), "PID 4")
        self.assertEqual(b.one_line("a\n  b\tc"), "a b c")
        self.assertEqual(b.clean_text("a\x00b"), "ab")
        self.assertEqual(b.clean_text("a\ud800b"), "a?b")
        self.assertEqual(b.as_int(float("inf"), 0), 0)
        self.assertEqual(b.as_int("1e999", 5), 5)

    def test_times(self):
        value = b.parse_system_time("2026-10-12T07:23:45.1234567Z")
        self.assertAlmostEqual(value % 60, 45.1234567, places=5)
        self.assertIsNone(b.parse_system_time("bad"))
        self.assertEqual(b.filetime_to_epoch(116444736000000000), 0.0)
        now = time.time()
        self.assertEqual(b.sane_time(now - 5), (now - 5, True))
        self.assertFalse(b.sane_time(603246995523.0)[1])
        self.assertFalse(b.sane_time(-11644473600.0)[1])
        self.assertFalse(b.sane_time("x")[1])
        self.assertEqual(b.clock(-1e20), "??:??:??.???")


class Registry(unittest.TestCase):
    def test_diff(self):
        keys = {"", "Sub", "Gone", "Gone\\Deep"}
        old = (keys, {("", "A"): (4, 1), ("", "B"): (1, "x"), ("Gone", "V"): (4, 1), ("Gone\\Deep", "W"): (4, 2)}, keys)
        keys = {"", "Sub", "New", "New\\Inner"}
        new = (keys, {("", "A"): (4, 2), ("", "C"): (1, "y"), ("New", "N"): (4, 5)}, keys)
        changes = b.reg_diff(old, new)
        kinds = [(c[0], c[1], c[2]) for c in changes]
        self.assertIn(("key added", "New", None), kinds)
        self.assertNotIn(("key added", "New\\Inner", None), kinds)
        self.assertIn(("value changed", "", "A"), kinds)
        self.assertIn(("value added", "", "C"), kinds)
        self.assertIn(("value added", "New", "N"), kinds)
        self.assertIn(("value deleted", "", "B"), kinds)
        self.assertIn(("key deleted", "Gone", None), kinds)
        self.assertNotIn(("key deleted", "Gone\\Deep", None), kinds)
        self.assertFalse(any(c[0] == "value deleted" and c[1].startswith("Gone") for c in changes))

    def test_values_past_the_read_limit_are_never_reported_as_added_or_deleted(self):
        class Handle:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

        class Registry:
            KEY_READ = 1
            tree = {}

            @classmethod
            def OpenKey(cls, _hive, path, _reserved, _access):
                if path not in cls.tree:
                    raise OSError(path)
                return Handle(path)

            @classmethod
            def EnumValue(cls, handle, index):
                found = cls.tree[handle.path][0]
                if index >= len(found):
                    raise OSError("no more values")
                return found[index] + (4,)

            @classmethod
            def EnumKey(cls, handle, index):
                found = cls.tree[handle.path][1]
                if index >= len(found):
                    raise OSError("no more keys")
                return found[index]

        def read(tree):
            Registry.tree = tree
            return b.read_reg_tree(None, "Root", max_values=4)

        before = {"Root": ([("r", 1)], ["B", "D"]), "Root\\B": ([("b1", 1), ("b2", 2)], []),
                  "Root\\D": ([("d1", 1), ("d2", 2)], [])}
        after = {**before, "Root": ([("r", 1)], ["A", "B", "D"]), "Root\\A": ([("a", 1)], [])}
        shorter = {**before, "Root\\B": ([("b1", 1)], [])}
        saved = b.winreg
        try:
            b.winreg = Registry
            old, new, less = read(before), read(after), read(shorter)
        finally:
            b.winreg = saved
        kinds = lambda changes: [(c[0], c[1], c[2]) for c in changes]
        self.assertEqual(kinds(b.reg_diff(old, new)), [("key added", "A", None), ("value added", "A", "a")])
        self.assertEqual(kinds(b.reg_diff(new, old)), [("key deleted", "A", None)])
        self.assertEqual(kinds(b.reg_diff(old, less)), [("value deleted", "B", "b2")])

    def test_paths(self):
        self.assertEqual(b.split_reg_path("HKEY_CURRENT_USER\\Software\\X\\"), ("HKCU", "Software\\X"))
        self.assertEqual(b.split_reg_path("hklm\\SOFTWARE"), ("HKLM", "SOFTWARE"))
        sid = "S-1-5-21-1-2-3-1001"
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\MACHINE\\SOFTWARE\\X", sid), "HKLM\\SOFTWARE\\X")
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\USER\\%s\\Control Panel" % sid, sid), "HKCU\\Control Panel")
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\USER\\%s_Classes\\.jpg" % sid, sid),
                         "HKCU\\Software\\Classes\\.jpg")
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\USER\\S-1-5-18\\X", sid), "HKU\\S-1-5-18\\X")
        self.assertEqual(b.nice_reg_path("HKCU\\X", sid), "HKCU\\X")
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\USER\\%s1\\Software" % sid, sid), "HKU\\%s1\\Software" % sid)
        self.assertEqual(b.nice_reg_path("\\REGISTRY\\USER\\%s" % sid, sid), "HKCU")

    def test_device_map(self):
        mapper = b.DeviceMap()
        mapper.devices = [("\\device\\harddiskvolume3", "C:")]
        self.assertEqual(mapper.to_dos("\\Device\\HarddiskVolume3\\Windows\\a.exe"), "C:\\Windows\\a.exe")
        self.assertEqual(mapper.to_dos("\\??\\C:\\x"), "C:\\x")
        self.assertEqual(mapper.to_dos("\\Device\\Other\\x"), "\\Device\\Other\\x")


EVENTS_XML = "\n".join((
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error'/>",
    "<EventID Qualifiers='0'>1000</EventID><Level>2</Level><TimeCreated SystemTime='2026-10-12T07:23:45.1234567Z'/>",
    "<EventRecordID>4242</EventRecordID><Execution ProcessID='880' ThreadID='1'/><Channel>Application</Channel></System>",
    "<EventData><Data>Photos.exe</Data></EventData><RenderingInfo Culture='en-US'><Message>Faulting application name: Photos.exe",
    'second line</Message><Level>Error</Level><Task>(100)</Task></RenderingInfo></Event>',
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='TraceSelfTest'/>",
    "<EventID>999</EventID><Level>3</Level><TimeCreated SystemTime='2026-10-12T07:23:46Z'/><EventRecordID>4243</EventRecordID>",
    "<Channel>Application</Channel></System><EventData><Data Name='Text'>Trace self test event</Data></EventData></Event>",
))


class EventLog(unittest.TestCase):
    def test_parse(self):
        records = b.parse_events_xml(EVENTS_XML)
        self.assertEqual(len(records), 2)
        first, second = records
        self.assertEqual((first["id"], first["level"], first["record"], first["pid"]), (1000, 2, 4242, 880))
        self.assertEqual(first["channel"], "Application")
        self.assertEqual(first["data"], [("", "Photos.exe")])
        text, level = b.event_log_text(first)
        self.assertEqual(text, "Application: Error 1000 from Application Error: Faulting application name: Photos.exe")
        self.assertEqual(level, b.ERROR)
        text, level = b.event_log_text(second)
        self.assertEqual(text, "Application: Warning 999 from TraceSelfTest: Text=Trace self test event")
        self.assertEqual(level, b.WARN)

    def test_parse_broken_text(self):
        records = b.parse_events_xml("garbage " + EVENTS_XML.split("</Event>", 1)[0] + "</Event> <Event>broken")
        self.assertEqual(len(records), 1)
        self.assertEqual(b.parse_events_xml(""), [])

    def test_query_and_decoding(self):
        query = b.structured_query([("Application", "*[System[(EventRecordID > 5)]]"), ("System", "*")])
        self.assertIn('<Select Path="Application">*[System[(EventRecordID &gt; 5)]]</Select>', query)
        self.assertTrue(query.startswith('<QueryList><Query Id="0" Path="Application">'))
        self.assertEqual(b.decode_tool_output("\u00e7".encode("utf-8")), "\u00e7")
        self.assertEqual(b.decode_tool_output(b"\xef\xbb\xbfabc"), "abc")
        self.assertEqual(b.decode_tool_output(b"\xff\xfe" + "ab".encode("utf-16-le")), "ab")
        self.assertEqual(b.short_channel("Microsoft-Windows-Shell-Core/Operational"), "Shell-Core/Operational")

    def test_a_log_whose_newest_entry_cannot_be_read_waits_for_it(self):
        class Source(b.EventLogSource):
            def __init__(self):
                self.channels = ["Application", "System"]
                self.last = {}
                self.failures = 0
                self.one_by_one = False
                self.newest = {"Application": [10], "System": [None, None, 50]}
                self.asked = []

            def _newest(self, channel):
                values = self.newest[channel]
                return values.pop(0) if len(values) > 1 else values[0]

            def _query(self, selects, count):
                self.asked.append(list(selects))
                return [], ""

        source = Source()
        for channel in source.channels:
            source.last[channel] = source._newest(channel)
        source._poll()
        source._poll()
        application = ("Application", "*[System[(EventRecordID > 10)]]")
        self.assertEqual(source.asked, [[application], [application, ("System", "*[System[(EventRecordID > 50)]]")]])
        real = b.EventLogSource.__new__(b.EventLogSource)
        real.tool = "wevtutil"
        saved = b.run_hidden
        try:
            b.run_hidden = lambda cmd, _timeout: b.subprocess.CompletedProcess(cmd, 5, b"", b"Access is denied.")
            self.assertIsNone(real._newest("System"))
        finally:
            b.run_hidden = saved


class ProcMon(unittest.TestCase):
    def test_digest(self):
        digest = b.ProcmonDigest(own_pid=99, limit=100)
        digest.add(10.0, "Photos.exe", 5, "RegSetValue", "HKCU\\Control Panel\\Desktop\\Wallpaper", "SUCCESS")
        digest.add(11.0, "Photos.exe", 5, "RegQueryValue", "HKCU\\Control Panel\\Desktop", "SUCCESS")
        digest.add(12.0, "Photos.exe", 5, "RegOpenKey", "HKLM\\Y", "ACCESS DENIED")
        digest.add(13.0, "Photos.exe", 5, "RegQueryValue", "HKLM\\SomeOther", "SUCCESS")
        digest.add(14.0, "System", 4, "WriteFile", "C:\\x.txt", "SUCCESS")
        digest.add(15.0, "Bastard.exe", 99, "WriteFile", "C:\\log.txt", "SUCCESS")
        digest.add(16.0, "Procmon64.exe", 7, "WriteFile", "C:\\t.pml", "SUCCESS")
        digest.add(17.0, "app.exe", 8, "WriteFile", "C:\\wallpaper.jpg", "SUCCESS")
        digest.add(18.0, "app.exe", 8, "TCP Connect", "a to b", "ACCESS DENIED")
        digest.add(19.0, "app.exe", 8, "ReadFile", "C:\\Users\\me\\wallpaper theme.jpg", "SUCCESS")
        digest.add(20.0, "app.exe", 8, "ReadFile", "C:\\data.bin", "SUCCESS")
        rows = digest.ordered()
        self.assertEqual(digest.total, 11)
        self.assertEqual([row[0] for row in rows], [10.0, 11.0, 12.0, 13.0, 14.0, 17.0, 18.0, 19.0, 20.0])
        self.assertEqual(rows[2][5], "ACCESS DENIED")
        self.assertEqual(rows[2][7], b.ERROR)
        self.assertEqual(rows[0][6], b.KIND_REG)
        network = next(row for row in rows if row[0] == 18.0)
        self.assertEqual(network[6], b.KIND_NET)
        self.assertEqual((digest.denied, digest.reg_writes, digest.file_writes, digest.reads, digest.over),
                         (2, 1, 2, 4, 0))

    def test_kind_network(self):
        self.assertEqual(b.procmon_kind("TCP Send"), b.KIND_NET)
        self.assertEqual(b.procmon_kind("RegQueryValue"), b.KIND_REG)
        self.assertEqual(b.procmon_kind("ReadFile"), b.KIND_FILE)

    def test_time_of_day(self):
        day = time.mktime((2026, 10, 12, 13, 0, 0, 0, 0, -1))
        value = b.procmon_time_of_day("2:05:12.1234567 PM", day)
        self.assertAlmostEqual(value - day, 3912.1234567, places=4)
        self.assertAlmostEqual(b.procmon_time_of_day("14:05:12,5", day) - day, 3912.5, places=4)
        late = time.mktime((2026, 10, 12, 23, 59, 0, 0, 0, -1))
        self.assertAlmostEqual(b.procmon_time_of_day("00:00:30", late) - late, 90.0, places=3)
        self.assertEqual(b.procmon_time_of_day("nonsense", day), day)

    def test_csv(self):
        folder = tempfile.mkdtemp()
        try:
            rows = [["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"],
                    ["2:05:12.1 PM", "app.exe", "8", "RegSetValue", "HKCU\\X", "SUCCESS", "Type: REG_SZ"]]
            first = os.path.join(folder, "a.csv")
            with open(first, "w", encoding="utf-8-sig", newline="") as fh:
                fh.write("\r\n".join(",".join('"%s"' % cell for cell in row) for row in rows) + "\r\n")
            second = os.path.join(folder, "b.csv")
            with open(second, "w", encoding="utf-16", newline="") as fh:
                fh.write("\r\n".join("\t".join(row) for row in rows) + "\r\n")
            for path in (first, second):
                found = list(b.procmon_csv_rows(path))
                self.assertEqual(len(found), 1, path)
                self.assertEqual(found[0]["Process Name"], "app.exe")
                self.assertEqual(found[0]["Operation"], "RegSetValue")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_network_rows_keep_their_protocol(self):
        class Ev:
            def __init__(self, operation, protocol, path):
                self.event_class = type("C", (), {"name": "Network" if protocol else "File System"})()
                self.operation = type("O", (), {"csv_name": operation, "name": operation})()
                self.network_protocol = protocol
                self.result = 0
                self.date_filetime = b.FILETIME_EPOCH + 10000000
                self.process = type("P", (), {"process_name": "app.exe", "pid": 500})()
                self.path = path

        rows = [Ev("Send", "TCP", "10.0.0.2:50000 -> 10.0.0.9:443"), Ev("Receive", "UDP", "10.0.0.2:53 -> 10.0.0.9:53"),
                Ev("WriteFile", "", "C:\\x.txt")]

        class Reader:
            def __init__(self, _fh, **_options):
                pass

            def __len__(self):
                return len(rows)

            def __getitem__(self, index):
                return rows[index]

        folder = tempfile.mkdtemp()
        saved = (b.ProcmonLogsReader, b.procmon_result_text)
        try:
            pml = os.path.join(folder, "x.pml")
            with open(pml, "wb") as fh:
                fh.write(b"x")
            b.ProcmonLogsReader = Reader
            b.procmon_result_text = lambda _value: "SUCCESS"
            source = b.ProcMonSource.__new__(b.ProcMonSource)
            source.pml = pml
            source.session = type("S", (), {"abort_event": b.threading.Event(), "user_sid": "",
                                            "devices": b.DeviceMap()})()
            source.status = lambda *_args, **_options: None
            digest = b.ProcmonDigest(1, 100)
            ok, _info = source._read_pml(digest)
            self.assertTrue(ok)
            found = [(row[3], row[6]) for row in digest.ordered()]
            self.assertEqual(found, [("TCP Send", b.KIND_NET), ("UDP Receive", b.KIND_NET), ("WriteFile", b.KIND_FILE)])
        finally:
            b.ProcmonLogsReader, b.procmon_result_text = saved
            shutil.rmtree(folder, ignore_errors=True)


class NewSources(unittest.TestCase):
    def test_reg_helpers_guard(self):
        self.assertIsNone(b.reg_read_value(None, "Software\\X", "Y"))
        self.assertFalse(b.reg_key_exists(None, "Software\\X"))

    def test_source_registry(self):
        names = [cls.name for cls in b.SOURCE_TYPES]
        for wanted in (b.SRC_ETW, b.SRC_WMI, b.SRC_PROBE, b.SRC_TRACE):
            self.assertIn(wanted, names)
        self.assertEqual(b.ETW_GUID_NAMES["{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"], "Kernel-Registry")
        self.assertNotIn("{70EB4F03-C1DE-4F73-A051-33D13D541355}", b.ETW_GUID_NAMES)

    def test_wmi_watches_the_user_keys_where_wmi_can_see_them(self):
        self.assertEqual(b.wmi_reg_target("HKEY_CURRENT_USER", "Control Panel\\Desktop", "S-1-5-21-7"),
                         ("HKEY_USERS", "S-1-5-21-7\\\\Control Panel\\\\Desktop"))
        self.assertIsNone(b.wmi_reg_target("HKEY_CURRENT_USER", "Control Panel\\Desktop", ""))
        self.assertEqual(b.wmi_reg_target("HKEY_LOCAL_MACHINE", "SOFTWARE\\X", ""), ("HKEY_LOCAL_MACHINE", "SOFTWARE\\\\X"))
        calls = []

        class Event:
            def watch_for(self, **where):
                calls.append(where)
                raise RuntimeError("no events here")

        class Connection:
            RegistryValueChangeEvent = Event()

        class Module:
            @staticmethod
            def WMI(**options):
                calls.append(options)
                return Connection()

        class Com:
            @staticmethod
            def CoInitialize():
                return None

            @staticmethod
            def CoUninitialize():
                return None

        class Quiet:
            user_sid = "S-1-5-21-7"

            def __init__(self, hub):
                self.hub = hub

        hub = b.Hub(b.Exclusions(()))
        saved = (b.wmi_module, b.pythoncom)
        try:
            b.wmi_module, b.pythoncom = Module, Com
            b.WmiSource(Quiet(hub))._reg_watch()
        finally:
            b.wmi_module, b.pythoncom = saved
        self.assertEqual(calls[0], {"namespace": "default"})
        self.assertEqual(calls[1], {"Hive": "HKEY_USERS", "KeyPath": "S-1-5-21-7\\\\Control Panel\\\\Desktop",
                                    "ValueName": "WallPaper"})
        self.assertEqual(len(calls), 1 + len(b.WMI_REG_TARGETS))

    def test_a_broken_wmi_registry_watcher_waits_instead_of_spinning(self):
        calls = []
        first = threading.Event()

        def broken(timeout_ms):
            calls.append(timeout_ms)
            first.set()
            raise RuntimeError("the WMI service went away")

        class Event:
            @staticmethod
            def watch_for(**_where):
                return broken

        class Connection:
            RegistryValueChangeEvent = Event()

        class Module:
            @staticmethod
            def WMI(**_options):
                return Connection()

        class Com:
            CoInitialize = CoUninitialize = staticmethod(lambda: None)

        session = FakeSession()
        session.user_sid = "S-1-5-21-7"
        saved = (b.wmi_module, b.pythoncom)
        try:
            b.wmi_module, b.pythoncom = Module, Com
            source = b.WmiSource(session)
            source.timeout_exc = None
            worker = threading.Thread(target=source._reg_watch)
            worker.start()
            first.wait(5.0)
            time.sleep(0.2)
            session.stop_event.set()
            worker.join(5.0)
        finally:
            b.wmi_module, b.pythoncom = saved
        self.assertFalse(worker.is_alive())
        self.assertLess(len(calls), 5)

    def test_policy_and_shell_folder_probes(self):
        names = [name for _hive, _path, name in b.PROBE_POLICY_KEYS]
        self.assertIn("DisableWindowsSpotlightFeatures", names)
        personalization = "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"
        user = [(path, name) for hive, path, name in b.PROBE_POLICY_KEYS if hive == "HKCU"]
        self.assertIn((personalization, "NoLockScreen"), user)
        self.assertIn((personalization, "NoChangingLockScreen"), user)
        self.assertIn("Desktop", b.PROBE_SHELL_FOLDERS)
        self.assertIn("AppData", b.PROBE_SHELL_FOLDERS)
        self.assertTrue(hasattr(b.ProbeSource, "_shell_folders"))

    def test_appprivacy_words(self):
        self.assertEqual(b.PROBE_APPPRIVACY_WORDS[2], "2 (force deny)")
        self.assertEqual(b.PROBE_APPPRIVACY_WORDS[0], "0 (user in control)")

    def test_only_a_refusal_counts_as_denied(self):
        for text in ("Status=0x80070005", "Status=0xC0000022", "hr=0x80070522", "Access is denied",
                     "[Kernel-File] Status=0xc0000022 | FileName=C:\\x.jpg"):
            self.assertTrue(b.says_denied(text), text)
        for text in ("Status=0x80070002", "Status=0x80070003", "hr=0x8007000E", "Status=0x800700051",
                     "Status=0x0", "FileName=C:\\Users\\me\\0x8007.txt"):
            self.assertFalse(b.says_denied(text), text)

    def etw_event(self, data):
        hub = b.Hub()
        source = b.EtwRawSource(FakeSession(hub))
        source.own_pid = -1
        source._on((12, data))
        events = drained(hub)
        self.assertEqual(len(events), 1)
        return events[0]

    def test_an_etw_row_is_a_problem_only_when_it_was_refused(self):
        header = {"ProcessId": 4321, "TimeStamp": filetime(time.time())}
        missing = self.etw_event({"EventHeader": header, "ProviderName": "Kernel-File", "Status": "0x80070002",
                                  "FileName": "C:\\gone.jpg"})
        self.assertEqual(missing.level, b.INFO)
        refused = self.etw_event({"EventHeader": header, "ProviderName": "Kernel-File", "Status": "0xc0000022",
                                  "FileName": "C:\\x.jpg"})
        self.assertEqual(refused.level, b.ERROR)

    def test_an_etw_row_names_its_process(self):
        b.PROCESS_NAMES.put(4321, "Photos.exe")
        header = {"ProcessId": 4321, "TimeStamp": filetime(time.time())}
        ev = self.etw_event({"EventHeader": header, "ProviderName": "Kernel-Registry", "KeyName": "HKCU\\X"})
        self.assertEqual((ev.pid, ev.proc), (4321, "Photos.exe"))
        self.assertEqual(ev.who(), "Photos.exe (PID 4321)")
        self.assertEqual(b.process_exclusion_from(ev), "ETW | | process=Photos.exe")

    def test_an_etw_row_with_no_fields_names_its_event(self):
        header = {"ProcessId": 4321, "TimeStamp": filetime(time.time()),
                  "ProviderId": "{315A8872-923E-4EA2-9889-33CD4754BF64}"}
        bare = self.etw_event({"EventHeader": header, "Task Name": "MICROSOFT-WINDOWS-IMMERSIVE-SHELL",
                               "Description": "", "EventExtendedData": {}})
        self.assertEqual(bare.text, "[Immersive-Shell] event 12")
        shell = dict(header, ProviderId="{30336ED4-E327-447C-9DE0-51B652C86108}")
        named = self.etw_event({"EventHeader": shell, "Task Name": "MICROSOFT-WINDOWS-SHELL-CORE", "Description": "",
                                "pszFilePath": "C:\\Windows\\img0.jpg", "EventExtendedData": {}})
        self.assertEqual(named.text, "[Shell-Core] pszFilePath=C:\\Windows\\img0.jpg")

    def test_trace_tools_rows_keep_the_time_they_happened(self):
        folder = tempfile.mkdtemp(prefix="bastard_trace_")
        try:
            start = time.time() - 120
            rows = [["Event Name", "Type", "PID", "Clock-Time", "User Data"],
                    ["FileIo", "Create", "0x00001F40", str(filetime(start + 2.5)), "C:\\a.jpg"],
                    ["Registry", "SetValue", "0x00001F40", str(filetime(start + 30.0)), "Status=0xC0000022"],
                    ["FileIo", "Create", "0x00001F40", str(filetime(start + 31.0)), "Status=0x80070002"]]
            path = os.path.join(folder, "trace.csv")
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write("\r\n".join(",  ".join(row) for row in rows) + "\r\n")
            hub = b.Hub()
            session = FakeSession(hub)
            session.markers = [(1, start + 1.0), (2, start + 60.0)]
            source = b.TraceToolSource(session)
            source.mode = "logman"
            source.etl = os.path.join(folder, "trace.etl")
            source._publish(path)
            events = drained(hub)
            listed = [ev for ev in events if ev.source == b.SRC_TRACE]
            self.assertEqual(len(listed), 3)
            self.assertAlmostEqual(listed[0].ts, start + 2.5, places=3)
            self.assertAlmostEqual(listed[2].ts, start + 31.0, places=3)
            self.assertEqual([ev.level for ev in listed], [b.INFO, b.ERROR, b.INFO])
            marks = [ev.text for ev in events if ev.kind == b.KIND_MARK]
            self.assertIn("Marker 1: Trace Tools listed 1 event in the 6 seconds after it", marks)
            self.assertIn("Marker 2: Trace Tools listed 0 events in the 6 seconds after it", marks)
            self.assertIsNone(b.trace_row_time({"Clock-Time": "not a time"}))
            self.assertIsNone(b.trace_row_time({"Event Name": "x"}))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_procmon_is_looked_for_next_to_bastard(self):
        folder = tempfile.mkdtemp(prefix="bastard_pm_")
        saved = b.PROGRAM_DIR
        try:
            b.PROGRAM_DIR = folder
            path = os.path.join(folder, "Procmon64.exe")
            open(path, "w").close()
            self.assertEqual(b.find_procmon(), path)
            self.assertFalse(hasattr(b, "program_dir"))
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_missing_service_is_not_a_warning(self):
        replies = {"Dwm": (1060, "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:"),
                   "Themes": (0, "SERVICE_NAME: Themes\n        STATE              : 4  RUNNING")}
        hub = b.Hub()
        saved = b.run_text
        try:
            b.run_text = lambda cmd, _timeout: replies.get(cmd[-1], (0, "        STATE              : 1  STOPPED"))
            b.ProbeSource(FakeSession(hub))._services()
        finally:
            b.run_text = saved
        rows = {ev.text.split(" ")[0]: ev for ev in drained(hub) if ev.text != "J: services"}
        self.assertEqual(rows["Dwm"].text, "Dwm is not installed as a service")
        self.assertEqual(rows["Dwm"].level, b.INFO)
        self.assertEqual(rows["Themes"].level, b.INFO)
        self.assertEqual(rows["AppXSvc"].level, b.WARN)

    def test_rows_about_our_own_helpers_are_left_out(self):
        class Proc:
            def __init__(self, pid):
                self.pid = pid

            def parent(self):
                return None

        class Hit:
            def __init__(self, pid, ppid, name):
                self.ProcessId = pid
                self.ParentProcessId = ppid
                self.Name = name
                self.CommandLine = name

        session = FakeSession(b.Hub())
        hits = [Hit(4321, 100, "sc.exe"), Hit(4400, 640, "notepad.exe"), Hit(4500, 200, "conhost.exe")]

        def watcher(timeout_ms=0):
            if hits:
                return hits.pop(0)
            session.stop_event.set()
            return None

        class Module:
            @staticmethod
            def WMI(**_options):
                process = type("Process", (), {"watch_for": staticmethod(lambda _kind: watcher)})
                return type("Connection", (), {"Win32_Process": process})()

        class Com:
            @staticmethod
            def CoInitialize():
                return None

            @staticmethod
            def CoUninitialize():
                return None

        class Windows(b.WindowsSource):
            def __init__(self, hub, owners):
                self.hub = hub
                self.session = FakeSession(hub)
                self.shown = {}
                self.dialogs = {}
                self.last_front = None
                self.failures = 0
                self.owners = owners
                user = type("User", (), {"GetAncestor": staticmethod(lambda hwnd, _flag: hwnd)})()
                self.api = type("Api", (), {"user": user, "get_long": staticmethod(lambda _hwnd, _index: 0)})()

            def _text(self, hwnd):
                return "Window %d" % hwnd

            def _class(self, _hwnd):
                return "Frame"

            def _owner(self, hwnd):
                return self.owners[hwnd]

            def _when(self, _ms):
                return time.time()

            def _dialog_texts(self, _hwnd):
                return []

        saved = (b.wmi_module, b.pythoncom, b.psutil, b.OWN_TREE)
        try:
            b.wmi_module, b.pythoncom = Module, Com
            b.psutil = type("Psutil", (), {"Process": Proc})
            b.OWN_TREE = b.OwnTree(100)
            b.OWN_TREE.note(200, 100, None, "powershell.exe")
            b.OWN_TREE.note(300, 100, None, "Procmon64.exe")
            wmi = b.WmiSource(session)
            wmi.timeout_exc = None
            wmi._proc_watch()
            windows = Windows(session.hub, {1: (300, "Procmon64.exe", ""), 2: (900, "explorer.exe", "")})
            for kind in (b.EVENT_OBJECT_CREATE, b.EVENT_OBJECT_SHOW, b.EVENT_SYSTEM_FOREGROUND,
                         b.EVENT_SYSTEM_DIALOGSTART, b.EVENT_SYSTEM_DIALOGEND, b.EVENT_OBJECT_DESTROY):
                for hwnd in (1, 2):
                    windows._on_event(None, kind, hwnd, 0, 0, 0, 0)
        finally:
            b.wmi_module, b.pythoncom, b.psutil, b.OWN_TREE = saved
        events = drained(session.hub)
        self.assertEqual(windows.failures, 0)
        self.assertEqual([ev.text for ev in events if ev.source == b.SRC_WMI],
                         ["WMI saw a new process: notepad.exe (PID 4400)"])
        shown = [ev.text for ev in events if ev.source == b.SRC_WIN]
        self.assertEqual(len(shown), 6, shown)
        self.assertTrue(all(text.endswith("Window 2 (explorer.exe)") for text in shown), shown)

    def test_a_program_whose_parent_id_was_reused_is_not_ours(self):
        class Proc:
            parents = {5000: None, 4600: 200}

            def __init__(self, pid):
                self.pid = pid

            def ppid(self):
                return 1234 if self.pid == 5000 else self.parents.get(self.pid, 0)

            def parent(self):
                found = self.parents.get(self.pid)
                return Proc(found) if found else None

        saved = (b.psutil, b.OWN_TREE)
        try:
            b.psutil = type("Psutil", (), {"Process": Proc})
            b.OWN_TREE = b.OwnTree(100)
            b.OWN_TREE.note(1234, 100, None, "sc.exe")
            b.OWN_TREE.note(200, 100, None, "powershell.exe")
            self.assertFalse(b.ours(5000, "explorer.exe"))
            self.assertTrue(b.ours(4600, "conhost.exe"))
            self.assertTrue(b.ours(1234, "sc.exe"))
            self.assertTrue(b.ours(7000, "x.exe", 100))
            self.assertFalse(b.ours(7000, "x.exe", 0))
            self.assertFalse(b.ours(0))
        finally:
            b.psutil, b.OWN_TREE = saved

    def test_a_folder_in_another_profile_is_outside_yours(self):
        values = {"Desktop": "C:\\Users\\Alice\\Desktop", "AppData": "C:\\Users\\Ali\\AppData\\Roaming",
                  "Local AppData": "C:\\Users\\Ali", "My Pictures": "D:\\Pictures"}
        hub = b.Hub()
        saved = (b.reg_read_value, os.environ.get("USERPROFILE"))
        try:
            b.reg_read_value = lambda _hive, path, name: values.get(name) if path.endswith("User Shell Folders") else None
            os.environ["USERPROFILE"] = "C:\\Users\\Ali"
            b.ProbeSource(FakeSession(hub))._shell_folders()
        finally:
            b.reg_read_value = saved[0]
            if saved[1] is None:
                os.environ.pop("USERPROFILE", None)
            else:
                os.environ["USERPROFILE"] = saved[1]
        levels = {ev.text.split("[")[1].split("]")[0]: ev.level for ev in drained(hub) if "[" in ev.text}
        self.assertEqual(levels, {"Desktop": b.WARN, "AppData": b.INFO, "Local AppData": b.INFO, "My Pictures": b.WARN})

    def test_appprivacy_reads_every_policy_and_names_a_photos_deny(self):
        listed = {"HKLM": [("LetAppsAccessCamera", 2), ("LetAppsRunInBackground", 0),
                           ("LetAppsAccessAccountInfo_ForceDenyTheseApps", ["Microsoft.Windows.Photos_8wekyb3d8bbwe"]),
                           ("LetAppsAccessCamera_ForceDenyTheseApps", ["Contoso.App_123"])]}
        hub = b.Hub()
        saved = (b.reg_values, b.hive_handle)
        try:
            b.hive_handle = lambda name: name
            b.reg_values = lambda hive, _path: listed.get(hive)
            b.ProbeSource(FakeSession(hub))._appprivacy()
            rows = {ev.text: ev for ev in drained(hub)}
            listed = {}
            hub = b.Hub()
            b.ProbeSource(FakeSession(hub))._appprivacy()
            missing = [ev.text for ev in drained(hub)]
        finally:
            b.reg_values, b.hive_handle = saved
        self.assertEqual(rows["HKLM AppPrivacy [LetAppsAccessCamera] = 2 (force deny)"].level, b.WARN)
        self.assertEqual(rows["HKLM AppPrivacy [LetAppsRunInBackground] = 0 (user in control)"].level, b.INFO)
        deny = rows["HKLM AppPrivacy [LetAppsAccessAccountInfo_ForceDenyTheseApps] denies Microsoft Photos"]
        self.assertEqual(deny.level, b.ERROR)
        self.assertIn("Why only Photos: this policy holds back Store apps alone", deny.detail)
        self.assertIn("To undo: delete the value LetAppsAccessAccountInfo_ForceDenyTheseApps from that key", deny.detail)
        self.assertEqual(rows["HKLM AppPrivacy [LetAppsAccessCamera_ForceDenyTheseApps] = Contoso.App_123"].level, b.INFO)
        self.assertEqual(missing, ["B: AppPrivacy policy", "AppPrivacy key is not there"])

    def test_the_consent_store_is_read_for_photos_too(self):
        values = {("HKCU", b.CONSENT_STORE + "\\picturesLibrary"): "Allow",
                  ("HKCU", b.CONSENT_STORE + "\\picturesLibrary\\" + b.PHOTOS_FAMILY): "Deny",
                  ("HKLM", b.CONSENT_STORE + "\\documentsLibrary"): "Deny"}
        hub = b.Hub()
        saved = (b.reg_read_value, b.hive_handle)
        try:
            b.hive_handle = lambda name: name
            b.reg_read_value = lambda hive, path, name: values.get((hive, path)) if name == "Value" else None
            b.ProbeSource(FakeSession(hub))._consentstore()
        finally:
            b.reg_read_value, b.hive_handle = saved
        rows = {ev.text: ev for ev in drained(hub)}
        own = rows["HKCU picturesLibrary = Deny for Microsoft Photos"]
        self.assertEqual(own.level, b.ERROR)
        self.assertIn("Why only Photos: only Store apps ask for this permission", own.detail)
        self.assertIn("To undo: Settings > Privacy & security > Pictures, turn access back on for Microsoft Photos.",
                      own.detail)
        self.assertEqual(rows["HKCU picturesLibrary = Allow"].level, b.INFO)
        whole = rows["HKLM documentsLibrary = Deny"]
        self.assertEqual(whole.level, b.ERROR)
        self.assertIn("To undo: Settings > Privacy & security > Documents, turn access back on.", whole.detail)
        self.assertEqual(rows["HKLM graphicsCaptureProgrammatic = unset"].level, b.INFO)

    def test_a_disabled_service_is_a_problem_and_a_stopped_manual_one_is_not(self):
        replies = {"Themes": (0, "        STATE              : 4  RUNNING"),
                   "Dwm": (1060, "[SC] OpenService FAILED 1060:")}
        starts = {"Themes": 2, "AppXSvc": 3, "camsvc": 4, "ShellHWDetection": 2}
        hub = b.Hub()
        saved = (b.run_text, b.reg_read_value, b.hive_handle)
        try:
            b.hive_handle = lambda name: name
            b.run_text = lambda cmd, _timeout: replies.get(cmd[-1], (0, "        STATE              : 1  STOPPED"))
            b.reg_read_value = lambda _hive, path, name: starts.get(path.rsplit("\\", 1)[-1]) if name == "Start" else None
            b.ProbeSource(FakeSession(hub))._services()
        finally:
            b.run_text, b.reg_read_value, b.hive_handle = saved
        rows = {ev.text.split(" ")[0]: ev for ev in drained(hub) if ev.text != "J: services"}
        self.assertEqual((rows["Themes"].text, rows["Themes"].level), ("Themes is running and starts automatically", b.INFO))
        self.assertEqual((rows["AppXSvc"].text, rows["AppXSvc"].level),
                         ("AppXSvc (AppX Deployment Service) is stopped and starts when it is needed", b.INFO))
        self.assertEqual((rows["camsvc"].text, rows["camsvc"].level),
                         ("camsvc (Capability Access Manager Service) is disabled", b.ERROR))
        self.assertIn("Why only Photos: Store apps such as Photos ask this service", rows["camsvc"].detail)
        self.assertIn("To undo: set Start back to 3 under that key", rows["camsvc"].detail)
        self.assertEqual(rows["ShellHWDetection"].level, b.WARN)
        self.assertEqual(rows["ClipSVC"].level, b.WARN)
        self.assertEqual(rows["Dwm"].level, b.INFO)
        self.assertEqual(set(rows), set(b.PROBE_SERVICES))

    def test_winrt_lists_the_shell_packages_and_judges_photos(self):
        out = "\n".join([
            "IsSupported=True",
            'PHOTOS={"Name":"Microsoft.Windows.Photos","Status":"Tampered","Version":"2024.1","PackageFullName":"P_1"}',
            "PACKAGE=Microsoft.LockApp||",
            "PACKAGE=Microsoft.Windows.ShellExperienceHost|Ok|10.0.1",
            "PACKAGE=Microsoft.Windows.StartMenuExperienceHost|NeedsRemediation|10.0.2",
            "PACKAGE=MicrosoftWindows.Client.CBS||",
        ])
        hub = b.Hub()
        scripts = []
        saved = b.run_text

        def fake(cmd, _timeout):
            scripts.append(cmd[-1])
            return 0, out
        try:
            b.run_text = fake
            b.ProbeSource(FakeSession(hub))._winrt()
        finally:
            b.run_text = saved
        self.assertIn("@('Microsoft.LockApp','Microsoft.Windows.ShellExperienceHost',", scripts[0])
        self.assertIn("Select-Object Name,@{n='Status';e={[string]$_.Status}},Version,PackageFullName |", scripts[0])
        rows = {ev.text: ev for ev in drained(hub)}
        lock = rows["Microsoft.LockApp is not installed"]
        self.assertEqual(lock.level, b.WARN)
        self.assertIn("Windows uses this package for the lock screen.", lock.detail)
        self.assertIn("Get-AppxPackage -AllUsers Microsoft.LockApp", lock.detail)
        self.assertEqual(rows["Microsoft.Windows.ShellExperienceHost is installed, version 10.0.1"].level, b.INFO)
        self.assertEqual(rows["Microsoft.Windows.StartMenuExperienceHost is installed but its package status is "
                              "NeedsRemediation"].level, b.ERROR)
        self.assertEqual(rows["MicrosoftWindows.Client.CBS is not installed"].level, b.INFO)
        photos = rows["Microsoft Photos is installed but its package status is Tampered"]
        self.assertEqual(photos.level, b.ERROR)
        self.assertIn("press Repair", photos.detail)
        self.assertFalse(any(text.startswith("PACKAGE=") for text in rows))

    def test_the_photos_package_line_is_judged(self):
        for text, wanted in (("", "Microsoft Photos is not installed for this user"),
                             ('{"Name":"Microsoft.Windows.Photos","Status":"Ok"}', None),
                             ('{"Name":"Microsoft.Windows.Photos","Status":0}', None),
                             ('[{"Status":"Modified","PackageFullName":"P_2"}]',
                              "Microsoft Photos is installed but its package status is Modified"),
                             ("not json", None)):
            hub = b.Hub()
            b.ProbeSource(FakeSession(hub))._photos(text)
            self.assertEqual([ev.text for ev in drained(hub)], [wanted] if wanted else [], text)

    def test_a_policy_that_locks_the_background_is_a_problem(self):
        keys = (("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop", "NoChangingWallpaper"),
                ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", "DisableWindowsSpotlightFeatures"),
                ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "Wallpaper"),
                ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization", "NoLockScreen"))
        values = {"NoChangingWallpaper": 1, "DisableWindowsSpotlightFeatures": 1, "Wallpaper": ""}
        hub = b.Hub()
        saved = (b.reg_read_value, b.PROBE_POLICY_KEYS)
        try:
            b.PROBE_POLICY_KEYS = keys
            b.reg_read_value = lambda _hive, _path, name: values.get(name)
            b.ProbeSource(FakeSession(hub))._policy()
        finally:
            b.reg_read_value, b.PROBE_POLICY_KEYS = saved
        rows = {ev.text.split("[")[1].split("]")[0]: ev for ev in drained(hub) if "[" in ev.text}
        self.assertEqual(rows["NoChangingWallpaper"].level, b.ERROR)
        self.assertIn(b.LOCKING_NOTE, rows["NoChangingWallpaper"].detail)
        self.assertIn("To undo: delete the value NoChangingWallpaper from that key", rows["NoChangingWallpaper"].detail)
        self.assertEqual(rows["DisableWindowsSpotlightFeatures"].level, b.CHANGE)
        self.assertEqual(rows["Wallpaper"].level, b.CHANGE)
        self.assertEqual(rows["NoLockScreen"].level, b.INFO)

    def test_probes_end_with_a_verdict(self):
        hub = b.Hub()
        probe = b.ProbeSource(FakeSession(hub))
        probe._say("camsvc is disabled", b.ERROR)
        probe._say("ShellHWDetection is stopped although it starts automatically", b.WARN)
        probe._summarize()
        last = drained(hub)[-1]
        self.assertEqual((last.text, last.level), ("Probes found 1 problem: camsvc is disabled", b.ERROR))
        self.assertIn("Warnings:\n  ShellHWDetection is stopped although it starts automatically", last.detail)
        hub = b.Hub()
        probe = b.ProbeSource(FakeSession(hub))
        for index in range(5):
            probe._say("problem %d" % index, b.ERROR)
        probe._summarize()
        self.assertEqual(drained(hub)[-1].text, "Probes found 5 problems: problem 0; problem 1; problem 2; and 2 more")
        hub = b.Hub()
        probe = b.ProbeSource(FakeSession(hub))
        probe._say("Themes is running and starts automatically")
        probe._say("AppXSvc is stopped", b.WARN)
        probe._summarize()
        last = drained(hub)[-1]
        self.assertEqual((last.text, last.level), ("Probes found no setting known to stop Photos from setting the "
                                                   "wallpaper, and 1 warning to look at", b.INFO))
        self.assertIn("Problems:\n  none", last.detail)

    def test_a_probe_row_the_filter_leaves_out_stays_out_of_the_verdict(self):
        hub = b.Hub(b.Exclusions(b.DEFAULT_EXCLUSIONS))
        probe = b.ProbeSource(FakeSession(hub))
        probe._say("DisallowRun [1] = photos.exe", b.ERROR)
        probe._summarize()
        rows = drained(hub)
        self.assertEqual([ev.text for ev in rows],
                         ["Probes found no setting known to stop Photos from setting the wallpaper"])
        self.assertEqual(probe.problems, [])

    def test_the_probes_panel_line_counts_problems_and_warnings(self):
        hub = b.Hub()
        saved = (b.run_text, b.win32security)
        try:
            b.run_text = lambda _cmd, _timeout: (None, "not here")
            b.win32security = None
            b.ProbeSource(FakeSession(hub))._run()
        finally:
            b.run_text, b.win32security = saved
        rows = drained(hub)
        state, note = hub.snapshot()[0][b.SRC_PROBE]
        self.assertEqual(state, "done")
        problems = sum(1 for ev in rows[:-1] if ev.level == b.ERROR)
        warnings = sum(1 for ev in rows[:-1] if ev.level == b.WARN)
        self.assertEqual(note, "%s, %s" % (b.plural(problems, "problem"), b.plural(warnings, "warning")))
        self.assertTrue(rows[-1].text.startswith("Probes found"), rows[-1].text)
        self.assertIn("N: desktop background", [ev.text for ev in rows])
        self.assertIn("M: folder owners", [ev.text for ev in rows])

    def test_a_slideshow_background_is_pointed_out(self):
        for value, level, text in ((2, b.CHANGE, "the desktop background is a slideshow (BackgroundType 2)"),
                                   (3, b.CHANGE, "the desktop background is Windows Spotlight (BackgroundType 3)"),
                                   (0, b.INFO, "the desktop background is a picture (BackgroundType 0)"),
                                   (None, b.INFO, "BackgroundType is not set")):
            hub = b.Hub()
            saved = b.reg_read_value
            try:
                b.reg_read_value = lambda _hive, _path, _name, found=value: found
                b.ProbeSource(FakeSession(hub))._background()
            finally:
                b.reg_read_value = saved
            rows = [ev for ev in drained(hub) if ev.text != "N: desktop background"]
            self.assertEqual([(ev.text, ev.level) for ev in rows], [(text, level)])
            if value == 2:
                self.assertIn("Settings > Personalization > Background, choose Picture", rows[0].detail)

    def test_a_folder_owned_by_someone_else_is_a_problem(self):
        root = tempfile.mkdtemp()
        apps = os.path.join(root, "pf", "WindowsApps")
        data = os.path.join(root, "pd", "Microsoft", "Windows", "SystemData")
        os.makedirs(apps)
        os.makedirs(data)
        owners = {apps: "S-1-5-32-544", data: b.LOCAL_SYSTEM_SID}
        names = {"S-1-5-32-544": ("Administrators", "BUILTIN", 4), b.LOCAL_SYSTEM_SID: ("SYSTEM", "NT AUTHORITY", 5)}

        class Holder:
            def __init__(self, sid):
                self.sid = sid

            def GetSecurityDescriptorOwner(self):
                return self.sid

        class Security:
            SE_FILE_OBJECT = 1
            OWNER_SECURITY_INFORMATION = 1
            GetNamedSecurityInfo = staticmethod(lambda path, _kind, _flags: Holder(owners[path]))
            ConvertSidToStringSid = staticmethod(lambda sid: sid)
            LookupAccountSid = staticmethod(lambda _system, sid: names[sid])

        hub = b.Hub()
        saved = (b.win32security, os.environ.get("ProgramFiles"), os.environ.get("ProgramData"))
        try:
            b.win32security = Security
            os.environ["ProgramFiles"] = os.path.join(root, "pf")
            os.environ["ProgramData"] = os.path.join(root, "pd")
            b.ProbeSource(FakeSession(hub))._owners()
        finally:
            b.win32security = saved[0]
            for key, value in (("ProgramFiles", saved[1]), ("ProgramData", saved[2])):
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            shutil.rmtree(root, ignore_errors=True)
        rows = {ev.text: ev for ev in drained(hub)}
        wrong = rows["WindowsApps belongs to BUILTIN\\Administrators instead of TrustedInstaller"]
        self.assertEqual(wrong.level, b.ERROR)
        self.assertIn("takeown", wrong.detail)
        self.assertEqual(rows["SystemData belongs to NT AUTHORITY\\SYSTEM"].level, b.INFO)


class Timeline(unittest.TestCase):
    def test_store_order_and_window(self):
        store = b.Store(limit=5)
        self.assertTrue(store.add([event(1.0), event(2.0)]))
        self.assertFalse(store.add([event(1.5)]))
        self.assertEqual([ev.ts for ev in store.events()], [1.0, 1.5, 2.0])
        self.assertEqual([ev.ts for ev in store.window(1.0, 2.0)], [1.5, 2.0])
        store.add([event(3.0), event(4.0), event(5.0)])
        self.assertEqual(store.dropped, 1)

    def test_store_sorts_only_when_it_is_read(self):
        store = b.Store(limit=10)
        self.assertFalse(store.add([event(3.0), event(1.0)]))
        self.assertTrue(store.unsorted)
        self.assertEqual([ev.ts for ev in store.events()], [1.0, 3.0])
        self.assertFalse(store.unsorted)

    def test_store_keeps_room_for_the_quiet_sources(self):
        store = b.Store(limit=100)
        store.add([event(index / 500.0, b.SRC_ETW, b.KIND_ETW, b.INFO) for index in range(500)])
        store.add([event(float(index) + 1.0, b.SRC_REG, b.KIND_REG, b.CHANGE) for index in range(15)])
        store.add([event(20.0, b.SRC_PM, b.KIND_REG, b.CHANGE, "TraceSelfTest [A] set")])
        kept = {}
        for ev in store.events():
            kept[ev.source] = kept.get(ev.source, 0) + 1
        self.assertEqual(kept[b.SRC_REG], 15)
        self.assertEqual(kept[b.SRC_PM], 1)
        self.assertEqual(kept[b.SRC_ETW], 80)
        self.assertEqual(store.dropped, 420)

    def test_sample_events_keeps_the_quiet_sources(self):
        reads = [event(index / 400.0, b.SRC_PM, b.KIND_FILE, b.INFO) for index in range(400)]
        quiet = [event(float(index) + 1.0, b.SRC_REG, b.KIND_REG, b.CHANGE) for index in range(5)]
        write = event(20.0, b.SRC_PM, b.KIND_REG, b.CHANGE, "TraceSelfTest [A] set")
        events = sorted(reads + quiet + [write], key=b.Event.key)
        self.assertEqual([ev for ev in events[:30] if ev.source != b.SRC_PM], [])
        picked = b.sample_events(events, 30)
        self.assertEqual(len([ev for ev in picked if ev.source == b.SRC_REG]), 5)
        self.assertIn(write, picked)
        self.assertLessEqual(len(picked), 30)
        self.assertEqual([ev.key() for ev in picked], sorted(ev.key() for ev in picked))

    def test_the_program_never_writes_to_windows(self):
        with io.open(SOURCE, "r", encoding="utf-8") as fh:
            text = fh.read()
        for banned in ("winreg.SetValue", "winreg.CreateKey", "winreg.DeleteKey", "winreg.DeleteValue",
                       "winreg.SaveKey", "KEY_SET_VALUE", "KEY_WRITE", "KEY_ALL_ACCESS",
                       "SPI_SETDESKWALLPAPER", "SPIF_", '"ab"', '"wb"', '"r+"', "startfile"):
            self.assertNotIn(banned, text, banned)
        self.assertFalse(hasattr(b.ProbeSource, "_transcode_write"))
        self.assertTrue(hasattr(b.ProbeSource, "_transcoded"))

    def test_exclusion_rules(self):
        rules = b.Exclusions(["ETW | info | [Kernel-File] | FileName=", "Trace Tools | info", "ProcMon | info"])
        self.assertTrue(rules.blocks("ETW", b.INFO, "[Kernel-File] Irp=0xFF | Status=0x0"))
        self.assertFalse(rules.blocks("ETW", b.INFO, "[Kernel-File] FileKey=0xFF | FileName=C:\\x.jpg"))
        self.assertFalse(rules.blocks("ETW", b.CHANGE, "[Kernel-File] Irp=0xFF | Status=0x0"))
        self.assertTrue(rules.blocks("ProcMon", b.INFO, "read QueryOpen C:\\x.dll"))
        self.assertFalse(rules.blocks("ProcMon", b.ERROR, "denied CreateFile C:\\x"))
        self.assertFalse(rules.blocks(b.SRC_SYSTEM, b.INFO, "Trace stopped after 32.0 s"))
        self.assertEqual(rules.blocked, 2)
        rules.enabled = False
        self.assertFalse(rules.blocks("ProcMon", b.INFO, "read QueryOpen C:\\x.dll"))

    def test_default_exclusions_keep_what_the_selftest_looks_for(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        wanted = [
            (b.SRC_SYSTEM, b.INFO, "Trace stopped after 32.0 s"),
            (b.SRC_SYSTEM, b.MARK, "Marker 1: the wallpaper was not written in the 6 seconds after it. 4 events (Files 4)"),
            (b.SRC_FILES, b.CHANGE, "File created: %s\\x.txt" % SELFTEST_WORK),
            (b.SRC_FILES, b.CHANGE, "File renamed: %s\\x.txt -> %s\\y.txt" % (SELFTEST_WORK, SELFTEST_WORK)),
            (b.SRC_FILES, b.CHANGE, "File deleted: %s\\y.txt" % SELFTEST_WORK),
            (b.SRC_FILES, b.CHANGE, "File changed: %s\\tick.txt" % SELFTEST_WORK),
            (b.SRC_PROC, b.INFO, "Started python.exe (PID 7) by python.exe (PID 1)"),
            (b.SRC_PROC, b.INFO, "Exited cmd.exe (PID 9) with exit code 7 after 0.0 s"),
            (b.SRC_REG, b.CHANGE, "HKCU\\Software\\TraceSelfTest [A] 1 (0x1) -> 2 (0x2)"),
            (b.SRC_REG, b.CHANGE, "HKCU\\Software\\TraceSelfTest [B] added"),
            (b.SRC_LOG, b.WARN, "Application: Trace self test event"),
            (b.SRC_WALL, b.INFO, "Wallpaper at start: C:\\x.jpg"),
            (b.SRC_PM, b.CHANGE, "registry RegSetValue HKCU\\Software\\TraceSelfTest [A]"),
            (b.SRC_WIN, b.INFO, "Window opened: Untitled - Notepad"),
        ]
        for source, level, text in wanted:
            self.assertFalse(rules.blocks(source, level, text), text)
        self.assertEqual(rules.blocked, 0)

    def test_an_empty_filter_stays_empty(self):
        folder = tempfile.mkdtemp(prefix="bastard_empty_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            rules = b.load_exclusions(path)
            self.assertEqual(rules.lines, list(b.DEFAULT_EXCLUSIONS))
            rules.set_lines([])
            self.assertEqual(b.save_exclusions(rules, path), "")
            back = b.load_exclusions(path)
            self.assertEqual(back.lines, [])
            self.assertFalse(back.blocks("ProcMon", b.INFO, "read QueryOpen C:\\x.dll"))
            kept = b.load_exclusions(path)
            kept.set_lines(list(b.DEFAULT_EXCLUSIONS)[1:])
            b.save_exclusions(kept, path)
            self.assertEqual(len(b.load_exclusions(path).lines), len(b.DEFAULT_EXCLUSIONS) - 1)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_defaults_leave_the_trace_tools_fallback_alone(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertFalse(rules.blocks(b.SRC_TRACE, b.INFO, "logman: EventName=FileIo | Type=Read | PID=4"))
        self.assertTrue(hasattr(b.TraceToolSource, "_leave_it_to_etw"))

    def test_the_defaults_are_the_thirty_two_the_owner_asked_for(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertEqual(len(rules.rules), 32)
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO,
                                     "read RegQueryValue HKCU\\SOFTWARE\\Microsoft\\Windows\\DWM"
                                     "\\ColorPrevalence"))
        self.assertTrue(rules.blocks(b.SRC_PROBE, b.INFO, "D: DisallowRun policy"))
        self.assertTrue(rules.blocks(b.SRC_REG, b.CHANGE, "HKLM\\...\\Certificates\\Root added"))
        listed = procmon_listed(rules, [("Photos.exe", "QueryOpen", "C:\\x.dll", "SUCCESS"),
                                        ("Photos.exe", "CreateFile", "C:\\x.dll", "SUCCESS")])
        self.assertEqual([ev.text for ev in listed], ["CreateFile C:\\x.dll"])

    def test_the_defaults_leave_out_the_procmon_rows_that_say_nothing(self):
        gone = [
            ("Photos.exe", "CloseFile", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "IRP_MJ_CLOSE", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "QueryOpen", "C:\\Pictures\\a.jpg", "FAST IO DISALLOWED"),
            ("Photos.exe", "QueryBasicInformationFile", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "QueryDirectory", "C:\\Pictures", "SUCCESS"),
            ("Photos.exe", "ReadFile", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "CreateFileMapping", "C:\\Pictures\\a.jpg", "FILE LOCKED WITH ONLY READERS"),
            ("svchost.exe", "LockFile", "C:\\ProgramData\\State.srd-shm", "SUCCESS"),
            ("svchost.exe", "UnlockFileSingle", "C:\\ProgramData\\State.srd-shm", "SUCCESS"),
            ("explorer.exe", "FileSystemControl", "C:\\Users\\me", "NOT REPARSE POINT"),
            ("explorer.exe", "DeviceIoControl", "C:\\Users\\me", "INVALID PARAMETER"),
            ("explorer.exe", "RegSetInfoKey", "HKCU\\Control Panel\\Desktop", "SUCCESS"),
            ("explorer.exe", "Thread Create", "", "SUCCESS"),
            ("explorer.exe", "Thread Exit", "", "SUCCESS"),
            ("explorer.exe", "RegQueryValue", "HKCU\\Control Panel\\Desktop\\WallPaper", "BUFFER OVERFLOW"),
            ("ctfmon.exe", "RegQueryValue", "HKLM\\SOFTWARE\\Microsoft\\Input\\Settings\\proc_1\\Mode",
             "NAME NOT FOUND"),
            ("explorer.exe", "CreateFile", "C:\\Windows\\@{ms-resource:logo.png}", "NAME INVALID"),
            ("explorer.exe", "CreateFile", "C:\\Pictures\\gone.jpg", "NAME NOT FOUND"),
            ("System", "WriteFile", "C:\\$Mft", "SUCCESS"),
            ("System", "WriteFile", "C:\\$LogFile", "SUCCESS"),
            ("System", "WriteFile", "D:\\$BitMap", "SUCCESS"),
            ("System", "WriteFile", "C:\\$Directory", "SUCCESS"),
            ("System", "WriteFile", "C:\\$Extend\\$UsnJrnl:$J", "SUCCESS"),
        ]
        kept = [
            ("explorer.exe", "RegQueryValue", "HKCU\\Control Panel\\Desktop\\WallPaper", "SUCCESS"),
            ("explorer.exe", "RegQueryValue",
             "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\\NoChangingWallPaper",
             "NAME NOT FOUND"),
            ("explorer.exe", "RegCreateKey", "HKCU\\Control Panel\\Desktop", "SUCCESS"),
            ("Photos.exe", "CreateFile", "C:\\Pictures\\a.jpg", "SUCCESS"),
            ("Photos.exe", "CreateFile", "C:\\Pictures\\Old\\a.jpg", "PATH NOT FOUND"),
            ("Photos.exe", "Load Image", "C:\\Windows\\System32\\Windows.UI.Xaml.dll", "SUCCESS"),
            ("explorer.exe", "Process Create", "C:\\Program Files\\Tool\\tool.exe", "SUCCESS"),
            ("explorer.exe", "SetBasicInformationFile", "C:\\Users\\me\\TranscodedWallpaper", "SUCCESS"),
            ("explorer.exe", "WriteFile", "C:\\Users\\me\\TranscodedWallpaper", "SUCCESS"),
            ("explorer.exe", "RegSetValue", "HKCU\\Control Panel\\Desktop\\WallPaper", "SUCCESS"),
            ("Photos.exe", "QueryOpen", "C:\\Users\\me\\TranscodedWallpaper", "ACCESS DENIED"),
            ("Photos.exe", "ReadFile", "C:\\Users\\me\\TranscodedWallpaper", "ACCESS DENIED"),
        ]
        listed = procmon_listed(b.Exclusions(b.DEFAULT_EXCLUSIONS), gone + kept)
        wanted = procmon_listed(b.Exclusions([]), kept)
        self.assertEqual(len(wanted), len(kept))
        self.assertEqual([ev.text for ev in listed], [ev.text for ev in wanted])

    def test_the_defaults_leave_out_the_shell_core_reads_unless_they_name_a_wallpaper(self):
        header = {"ProcessId": OTHER_PID, "TimeStamp": filetime(time.time())}
        gone = [
            (22043, {"EventHeader": header, "ProviderName": "Shell-Core", "EventExtendedData": {}}),
            (16725, {"EventHeader": header, "ProviderName": "Shell-Core",
                     "FMTID": "{28636aa6-953d-11d2-b5d6-00c04fd918d0}", "PID": 11}),
            (3005, {"EventHeader": header, "ProviderName": "Shell-Core"}),
            (19403, {"EventHeader": header, "ProviderName": "Shell-Core", "Name": "D:\\Desktop\\notes.txt"}),
        ]
        kept = [
            (19403, {"EventHeader": header, "ProviderName": "Shell-Core", "Name": "D:\\Desktop\\wallpaper.jpg"}),
            (5961, {"EventHeader": header, "ProviderName": "Shell-Core", "HRESULT": "0x80070005"}),
            (40, {"EventHeader": header, "ProviderName": "Immersive-Shell", "ZbandFrom": 2, "ZbandTo": 3}),
        ]
        listed = etw_listed(b.Exclusions(b.DEFAULT_EXCLUSIONS), gone + kept)
        wanted = etw_listed(b.Exclusions([]), kept)
        self.assertEqual(len(wanted), len(kept))
        self.assertEqual([ev.text for ev in listed], [ev.text for ev in wanted])

    def test_the_defaults_come_back_the_same_from_the_ini_file(self):
        folder = tempfile.mkdtemp(prefix="bastard_defaults_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            self.assertEqual(b.save_exclusions(b.Exclusions(b.DEFAULT_EXCLUSIONS), path), "")
            self.assertEqual(b.load_exclusions(path).lines, list(b.DEFAULT_EXCLUSIONS))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_defaults_leave_the_kernel_file_reads_out(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "[Kernel-File] Irp=0xFF | Status=0x0"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "[Microsoft-Windows-Kernel-File] Irp=0xFF"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "x", "", "Provider: Kernel-File\nFileName=C:\\a.jpg"))
        self.assertFalse(rules.blocks(b.SRC_ETW, b.CHANGE, "[Kernel-Registry] KeyObject=0xFF | ValueName=WallPaper"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "[Kernel-Registry] KeyObject=0xFF | ValueName=WallPaper"))
        self.assertFalse(rules.blocks(b.SRC_ETW, b.INFO, "[Shell-Core] wallpaper changed"))
        self.assertFalse(rules.blocks(b.SRC_PM, b.CHANGE, "file WriteFile C:\\TranscodedWallpaper"))

    def test_the_defaults_keep_the_kernel_file_writes_and_denials(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        for level in (b.CHANGE, b.WARN, b.ERROR):
            self.assertFalse(rules.blocks(b.SRC_ETW, level, "[Kernel-File] WriteFile | FileName=C:\\a.jpg"), level)
        self.assertFalse(rules.blocks(b.SRC_ETW, b.ERROR,
                                      "[Kernel-File] Status=0xc0000022 | FileName=TranscodedWallpaper"))
        self.assertEqual(rules.blocked, 0)

    def test_sort_keys_cover_every_column(self):
        self.assertEqual(tuple(sorted(b.SORT_KEYS)), tuple(sorted(b.TREE_COLUMNS)))
        for column in b.TREE_COLUMNS:
            self.assertIn(column, b.TREE_TITLES)
            self.assertIn(column, b.TREE_WIDTHS)
        rows = [event(3.0, b.SRC_REG, b.KIND_REG, b.CHANGE, "banana", "b.exe", 9),
                event(1.0, b.SRC_FILES, b.KIND_FILE, b.CHANGE, "apple", "a.exe", 2),
                event(2.0, b.SRC_PM, b.KIND_PROC, b.INFO, "cherry", "c.exe", 5)]
        self.assertEqual([ev.text for ev in sorted(rows, key=b.SORT_KEYS["event"])],
                         ["apple", "banana", "cherry"])
        self.assertEqual([ev.pid for ev in sorted(rows, key=b.SORT_KEYS["pid"], reverse=True)], [9, 5, 2])
        self.assertEqual([ev.ts for ev in sorted(rows, key=b.SORT_KEYS["time"])], [1.0, 2.0, 3.0])
        self.assertEqual([ev.proc for ev in sorted(rows, key=b.SORT_KEYS["process"])],
                         ["a.exe", "b.exe", "c.exe"])

    def test_exclusion_from_event(self):
        ev = event(1.0, b.SRC_ETW, b.KIND_FILE, b.INFO,
                   "[Kernel-File] Irp=0xFFFFCA02F50EB3D8 | ExtraInformation=0x18 | Status=0x0")
        self.assertEqual(b.exclusion_from(ev), "ETW | info | [Kernel-File] Irp")
        rules = b.Exclusions([b.exclusion_from(ev)])
        self.assertTrue(rules.blocks(ev.source, ev.level, ev.text))

    def test_a_match_rule_never_carries_a_pipe(self):
        for source, text in ((b.SRC_WIN, "Dialog opened: Error (app.exe): The file could not be opened | OK"),
                             (b.SRC_ETW, "[Microsoft-Windows-Shell-Core] Name=Explorer | Value=0x1 | Flags=12345"),
                             (b.SRC_TRACE, "logman: EventName=FileIo | Type=Read | PID=4")):
            ev = event(1.0, source, "Kind", b.INFO, text)
            line = b.exclusion_from(ev)
            self.assertEqual(line.count("|"), 2, line)
            self.assertTrue(b.Exclusions([line]).blocks(ev.source, ev.level, ev.text), line)

    def test_procmon_says_listed_for_what_reached_the_list(self):
        class Fake(b.ProcMonSource):
            def __init__(self, hub):
                self.hub = hub
                self.session = type("S", (), {"markers": []})()
                self.pml = "x.pml"
                self.states = []
                self.notes = []

            def status(self, state, note=""):
                self.states.append((state, note))

            def note(self, text, level=b.INFO, detail=""):
                self.notes.append(text)

        hub = b.Hub(b.Exclusions(["ProcMon | | explorer.exe"]))
        source = Fake(hub)
        digest = b.ProcmonDigest(1, 100)
        now = time.time()
        digest.add(now, "explorer.exe", 5, "RegQueryValue", "HKCU\\A", "SUCCESS")
        digest.add(now + 1, "explorer.exe", 5, "RegQueryValue", "HKCU\\B", "SUCCESS")
        digest.add(now + 2, "Photos.exe", 6, "RegSetValue", "HKCU\\C", "SUCCESS")
        source._publish(digest, "3 events")
        self.assertEqual(source.states[-1], ("done", "1 listed"))
        self.assertTrue(source.notes[0].startswith("read 3 events, listed 1 of 3:"), source.notes[0])
        self.assertNotIn("scope", source.notes[0])

    def test_one_unreadable_procmon_event_does_not_end_the_read(self):
        class Ev:
            def __init__(self, index):
                self.event_class = type("C", (), {"name": "Registry"})()
                self.operation = type("O", (), {"csv_name": "RegSetValue", "name": "RegSetValue"})()
                self.result = 0
                self.date_filetime = b.FILETIME_EPOCH + index * 10000000
                self.process = type("P", (), {"process_name": "app.exe", "pid": 500})()
                self.path = "HKCU\\Software\\Thing%d" % index

        class Reader:
            def __init__(self, _fh, **_options):
                pass

            def __len__(self):
                return 100

            def __getitem__(self, index):
                if index == 10:
                    raise ValueError("17 is not a valid RegistryOperation")
                return Ev(index)

        folder = tempfile.mkdtemp()
        saved = (b.ProcmonLogsReader, b.procmon_result_text)
        try:
            pml = os.path.join(folder, "x.pml")
            with open(pml, "wb") as fh:
                fh.write(b"x")
            b.ProcmonLogsReader = Reader
            b.procmon_result_text = lambda _value: "SUCCESS"
            source = b.ProcMonSource.__new__(b.ProcMonSource)
            source.pml = pml
            source.session = type("S", (), {"abort_event": b.threading.Event(), "user_sid": "",
                                            "devices": b.DeviceMap()})()
            source.status = lambda *_args, **_options: None
            digest = b.ProcmonDigest(1, 1000)
            ok, info = source._read_pml(digest)
            self.assertTrue(ok)
            self.assertEqual(len(digest.rows), 99)
            self.assertIn("1 could not be read", info)
            Reader.__getitem__ = lambda _self, _index: (_ for _ in ()).throw(ValueError("unknown"))
            ok, info = source._read_pml(b.ProcmonDigest(1, 1000))
            self.assertFalse(ok)
        finally:
            b.ProcmonLogsReader, b.procmon_result_text = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_trace_tools_counts_only_what_it_listed(self):
        class Fake(b.TraceToolSource):
            def __init__(self, session):
                self.session = session
                self.hub = session.hub
                self.mode = "logman"
                self.etl = "x.etl"
                self.notes = []
                self.states = []

            def note(self, text, level=b.INFO, detail=""):
                self.notes.append(text)

            def status(self, state, note=""):
                self.states.append((state, note))

        folder = tempfile.mkdtemp()
        saved = b.PROCMON_ROW_LIMIT
        start = time.time() - 120
        try:
            path = os.path.join(folder, "r.csv")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("Event Name,Type,PID,Clock-Time\n" + "".join(
                    "FileIo,%s,%d,%d\n" % ("Skip" if index < 2 else "Read", index, filetime(start + 2.0))
                    for index in range(12)))
            b.PROCMON_ROW_LIMIT = 10
            session = FakeSession(b.Hub(b.Exclusions(["Trace Tools | | Skip"])))
            session.markers = [(1, start + 1.0)]
            source = Fake(session)
            source._publish(path)
            self.assertEqual(source.hub.snapshot()[1].get(b.SRC_TRACE), 8)
            self.assertEqual(source.notes[-1], "logman listed 8 of 10 rows, and the capture holds more")
            self.assertEqual(source.states[-1], ("done", "8 listed"))
            marks = [ev.text for ev in drained(source.hub) if ev.kind == b.KIND_MARK]
            self.assertEqual(marks, ["Marker 1: Trace Tools listed 8 events in the 6 seconds after it"])
        finally:
            b.PROCMON_ROW_LIMIT = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_stop_before_every_source_started_fails_none(self):
        folder = tempfile.mkdtemp()
        saved = b.PROGRAM_DIR
        try:
            b.PROGRAM_DIR = folder
            hub = b.Hub(b.Exclusions([]))
            hub.reset(b.SOURCE_NAMES)
            session = b.Session(hub, b.parse_options([]))
            session.request_stop()
            session.begin()
            session.finish()
            status, _counts = hub.snapshot()
            self.assertEqual([name for name, value in status.items() if value[0] == "failed"], [])
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_marker_summary_at_stop_is_left_to_the_list_once_the_log_is_full(self):
        folder = tempfile.mkdtemp()
        saved = b.PROGRAM_DIR
        try:
            b.PROGRAM_DIR = folder
            hub = b.Hub(b.Exclusions([]))
            hub.reset(b.SOURCE_NAMES)
            session = b.Session(hub, b.parse_options([]))
            session.sources = []
            session.writer = b.LogWriter(os.path.join(folder, "t.log"), ["h"], 400)
            session.writer.start()
            hub.writer = session.writer
            for index in range(60):
                hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d %s" % (index, "x" * 40), b.CHANGE)
            for _ in range(100):
                if session.writer.capped:
                    break
                time.sleep(0.02)
            self.assertTrue(session.writer.capped)
            session.markers.append((1, time.time()))
            session.request_stop()
            session.finish()
            self.assertTrue(session.claim_marker(1))
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_exclusions_round_trip(self):
        folder = tempfile.mkdtemp(prefix="bastard_rules_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            rules = b.Exclusions(["ETW | info | [Kernel-File] | FileName=", "Files | change | tick.txt"], 7, False,
                                 40000)
            self.assertEqual(b.save_exclusions(rules, path), "")
            back = b.load_exclusions(path)
            self.assertEqual(back.lines, rules.lines)
            self.assertEqual(back.log_mb, 7)
            self.assertEqual(back.procmon_rows, 40000)
            self.assertFalse(back.enabled)
            self.assertEqual(b.load_exclusions(os.path.join(folder, "missing.ini")).lines,
                             list(b.DEFAULT_EXCLUSIONS))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_log_writer_stops_at_its_limit(self):
        folder = tempfile.mkdtemp(prefix="bastard_log_")
        try:
            path = os.path.join(folder, "trace.log")
            writer = b.LogWriter(path, ["header"], 400)
            writer.start()
            for index in range(400):
                writer.put(event(float(index), b.SRC_FILES, b.KIND_FILE, b.CHANGE, "line %d" % index))
            writer.close(["footer"], True)
            self.assertTrue(writer.dropped > 0)
            self.assertTrue(writer.capped)
            with open(path, "r", encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("reached its", body)
            self.assertTrue(len(body) < 4000)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_finished_log_is_under_the_limit_it_was_given(self):
        folder = tempfile.mkdtemp(prefix="bastard_cap_")
        try:
            path = os.path.join(folder, "trace.log")
            limit = 2 * 1024 * 1024
            writer = b.LogWriter(path, ["header"], limit)
            self.assertTrue(writer.start())
            text = "C:\\Users\\" + "\u015fehir\u00e7i\u011fi" * 12
            for index in range(20000):
                writer.put(event(float(index), b.SRC_FILES, b.KIND_FILE, b.CHANGE, text))
            writer.close(["footer line %d" % index for index in range(60)], True)
            self.assertTrue(writer.dropped > 0)
            self.assertTrue(writer.capped)
            self.assertLess(os.path.getsize(path), limit)
            self.assertGreater(os.path.getsize(path), limit // 2)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_log_bytes_counts_what_the_file_holds(self):
        text = "\u015fehir\u00e7i"
        self.assertEqual(b.log_bytes(text), len(text.encode("utf-8")))
        self.assertGreater(b.log_bytes(text), len(text))
        self.assertEqual(b.log_bytes("plain"), 5)

    def test_the_procmon_row_count_has_bounds_and_a_default(self):
        folder = tempfile.mkdtemp(prefix="bastard_rows_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            self.assertEqual(b.load_exclusions(path).procmon_rows, b.PROCMON_ROW_LIMIT)
            self.assertEqual(b.Exclusions().procmon_rows, b.PROCMON_ROW_LIMIT)
            for asked, kept in ((1, 1000), (0, 1000), (50000, 50000), (b.PROCMON_ROW_LIMIT * 4, b.PROCMON_ROW_LIMIT)):
                b.save_exclusions(b.Exclusions([], b.DEFAULT_LOG_MB, True, asked), path)
                self.assertEqual(b.load_exclusions(path).procmon_rows, kept)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_digest_lists_only_as_many_rows_as_it_was_allowed(self):
        digest = b.ProcmonDigest(999, 25)
        for index in range(400):
            digest.add("12:00:00.0000000", "explorer.exe", "4000", "RegQueryValue",
                       "HKCU\\Software\\Thing%d" % index, "SUCCESS")
        self.assertEqual(len(digest.rows), 25)
        self.assertEqual(digest.over, 375)
        self.assertEqual(digest.total, 400)
        self.assertTrue(digest.full())
        self.assertFalse(b.ProcmonDigest(999, 25).full())

    def test_old_captures_go_by_their_time_whatever_made_them(self):
        folder = tempfile.mkdtemp()
        saved = b.TRACE_DIR
        stamps = ["20261001_10000%d" % index for index in range(7)]
        try:
            b.TRACE_DIR = folder
            for index, stamp in enumerate(stamps):
                if index % 2:
                    names = ("Bastard_logman_%s.etl", "Bastard_providers_%s.txt", "Bastard_logman_%s.csv")
                else:
                    names = ("Bastard_%s.pml", "Bastard_%s-1.pml", "Bastard_%s.csv")
                for name in names:
                    with open(os.path.join(folder, name % stamp), "w") as handle:
                        handle.write("x")
            for name in ("notes.txt", "Bastard_%s.log" % stamps[0]):
                with open(os.path.join(folder, name), "w") as handle:
                    handle.write("x")
            b.tidy_captures(stamps[-1])
            left = sorted(os.listdir(folder))
        finally:
            b.TRACE_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)
        kept = sorted({b.CAPTURE_RE.match(name).group(1) for name in left if b.CAPTURE_RE.match(name)
                       and name.endswith(b.CAPTURE_SUFFIXES)})
        self.assertEqual(kept, stamps[2:])
        self.assertIn("notes.txt", left)
        self.assertIn("Bastard_%s.log" % stamps[0], left)
        self.assertEqual(len(left), 3 * 5 + 2)

    def test_a_rule_can_name_a_process(self):
        rules = b.Exclusions(["ProcMon | | explorer.exe"])
        self.assertTrue(rules.blocks("ProcMon", b.INFO, "RegQueryValue HKCU\\Software\\Thing", "explorer.exe"))
        self.assertTrue(rules.blocks("ProcMon", b.CHANGE, "RegSetValue HKCU\\Software", "Explorer.exe"))
        self.assertFalse(rules.blocks("ProcMon", b.INFO, "RegQueryValue HKCU\\Software", "Photos.exe"))
        self.assertFalse(rules.blocks("ProcMon", b.INFO, "RegQueryValue HKCU\\Software"))
        self.assertFalse(rules.blocks("Files", b.INFO, "wrote a file", "explorer.exe"))

    def test_a_process_rule_can_be_held_to_one_level(self):
        rules = b.Exclusions(["ProcMon | info | explorer.exe"])
        self.assertTrue(rules.blocks("ProcMon", b.INFO, "RegQueryValue HKCU", "explorer.exe"))
        self.assertFalse(rules.blocks("ProcMon", b.CHANGE, "RegSetValue HKCU", "explorer.exe"))

    def test_a_text_rule_still_matches_when_a_process_is_given(self):
        rules = b.Exclusions(list(b.DEFAULT_EXCLUSIONS))
        self.assertTrue(rules.blocks("ProcMon", b.INFO, "RegQueryValue HKCU\\Software\\Policies DisallowRun",
                                     "explorer.exe"))
        self.assertTrue(rules.blocks("ETW", b.INFO, "something Certificates something", "svchost.exe"))
        self.assertFalse(rules.blocks("ProcMon", b.CHANGE, "RegSetValue HKCU\\Control Panel\\Desktop",
                                      "explorer.exe"))

    def test_the_process_rule_the_menu_builds(self):
        ev = event(1.0, b.SRC_PM, "Registry", b.INFO, "RegQueryValue HKCU\\Software\\Thing", "explorer.exe")
        self.assertEqual(b.process_exclusion_from(ev), "ProcMon | | process=explorer.exe")
        rules = b.Exclusions([b.process_exclusion_from(ev)])
        self.assertTrue(rules.blocks(ev.source, ev.level, ev.text, ev.proc))
        self.assertTrue(rules.blocks(ev.source, b.ERROR, "WriteFile C:\\x", "Explorer.exe"))
        self.assertFalse(rules.blocks(ev.source, b.ERROR, "QueryOpen C:\\Windows\\explorer.exe: ACCESS DENIED",
                                      "Photos.exe", "Process: Photos.exe (PID 5)"))
        self.assertFalse(b.Exclusions(["| | process="]).blocks(b.SRC_REG, b.CHANGE, "HKCU\\X [A] added"))
        long_name = "x" * 200 + ".exe"
        line = b.process_exclusion_from(event(1.0, b.SRC_PM, "Registry", b.INFO, "RegQueryValue HKCU\\Y", long_name))
        self.assertTrue(b.Exclusions([line]).blocks(b.SRC_PM, b.INFO, "RegQueryValue HKCU\\Y", long_name))
        started = b.Exclusions(["Processes | | process=explorer.exe"])
        self.assertFalse(started.blocks(b.SRC_PROC, b.INFO, "Started Photos.exe (PID 7) by explorer.exe (PID 2)",
                                        "Photos.exe"))
        self.assertTrue(started.blocks(b.SRC_PROC, b.INFO, "Started explorer.exe (PID 2)", "explorer.exe"))
        self.assertEqual(b.process_exclusion_from(event(1.0, b.SRC_ETW, "ETW", b.INFO, "x", "")), "")
        self.assertEqual(b.process_exclusion_from(event(1.0, b.SRC_ETW, "ETW", b.INFO, "x", "   ")), "")

    def test_a_process_rule_never_silences_the_system_source(self):
        rules = b.Exclusions(["| | bastard.exe"])
        self.assertFalse(rules.blocks(b.SRC_SYSTEM, b.INFO, "Trace started", "Bastard.exe"))
        self.assertTrue(rules.blocks(b.SRC_PROC, b.INFO, "started", "Bastard.exe"))

    def test_a_rule_reads_the_detail_lines(self):
        path = ("\\Device\\HarddiskVolume3\\Users\\K\\AppData\\Roaming\\Microsoft"
                "\\SystemCertificates\\My\\Certificates\\9F1A3C7E2B5D8046A1C3E5F70928BD4C")
        parts = ["Pad%d=0x%s" % (index, "A" * 40) for index in range(16)] + ["FileName=" + path]
        detail = " | ".join(parts)
        text = b.one_line("[Kernel-File] " + detail, 600)
        body = "Provider: Kernel-File\nEvent ID: 12\n" + detail
        self.assertNotIn("certificates", text.lower())
        self.assertIn("certificates", body.lower())
        rules = b.Exclusions(["| | DisallowRun", "| | Certificates"])
        self.assertTrue(rules.blocks("ETW", b.INFO, text, "", body))
        self.assertFalse(rules.blocks("ETW", b.INFO, text, "", "Provider: Kernel-File\nEvent ID: 12"))

    def test_a_rule_matches_part_of_a_longer_word(self):
        rules = b.Exclusions(["| | Certificates"])
        self.assertTrue(rules.blocks("ETW", b.INFO, "opened SystemCertificates store"))
        self.assertTrue(rules.blocks("ETW", b.INFO, "plain", "", "detail holds SystemCertificates here"))
        self.assertFalse(rules.blocks("ETW", b.INFO, "nothing of the sort"))

    def test_the_fourth_part_rescues_on_the_detail_too(self):
        rules = b.Exclusions(["ETW | | Certificates | FileName="])
        self.assertTrue(rules.blocks("ETW", b.INFO, "x", "", "holds Certificates and no name"))
        self.assertFalse(rules.blocks("ETW", b.INFO, "x", "", "holds Certificates with FileName=C:\\a"))

    def test_the_hub_leaves_out_an_event_caught_by_its_detail(self):
        hub = b.Hub(b.Exclusions(["| | Certificates"]))
        self.assertIsNone(hub.emit("ETW", "File", "[Kernel-File] Pad=1", detail="FileName=SystemCertificates"))
        self.assertIsNotNone(hub.emit("ETW", "File", "[Kernel-File] Pad=1", detail="FileName=Wallpaper"))
        self.assertEqual(hub.exclusions.blocked, 1)

    def test_the_hub_stops_taking_events_once_the_trace_has_ended(self):
        hub = b.Hub()
        hub.reset([b.SRC_ETW, b.SRC_PM])
        self.assertIsNotNone(hub.emit(b.SRC_ETW, "ETW", "[Kernel-File] during the trace"))
        hub.closed = True
        self.assertIsNone(hub.emit(b.SRC_ETW, "ETW", "[Kernel-File] a leaked thread"))
        self.assertIsNone(hub.emit(b.SRC_PM, "Registry", "RegQueryValue HKCU"))
        self.assertEqual(hub.late, 2)
        self.assertIsNotNone(hub.emit(b.SRC_SYSTEM, b.KIND_MARK, "Marker 1"))
        _status, counts = hub.snapshot()
        self.assertEqual(counts.get(b.SRC_ETW), 1)
        self.assertIsNone(counts.get(b.SRC_PM))
        hub.reset([b.SRC_ETW, b.SRC_PM])
        self.assertFalse(hub.closed)
        self.assertEqual(hub.late, 0)
        self.assertIsNotNone(hub.emit(b.SRC_ETW, "ETW", "a new trace"))

    def test_nothing_reaches_the_ui_queue_after_the_trace_has_ended(self):
        hub = b.Hub()
        hub.reset([b.SRC_ETW])
        hub.emit(b.SRC_ETW, "ETW", "one")
        hub.closed = True
        for index in range(50):
            hub.emit(b.SRC_ETW, "ETW", "leak %d" % index)
        seen = []
        while True:
            try:
                seen.append(hub.ui.get_nowait())
            except queue.Empty:
                break
        self.assertEqual([ev.text for ev in seen], ["one"])
        self.assertEqual(hub.late, 50)

    def test_the_defaults_leave_the_chrome_rows_out(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO, "RegQueryValue HKCU\\Software", "chrome.exe"))
        self.assertTrue(rules.blocks(b.SRC_PM, b.CHANGE, "WriteFile C:\\Temp\\a", "Chrome.exe"))
        self.assertTrue(rules.blocks(b.SRC_PM, b.ERROR, "QueryOpen C:\\x", "chrome.exe"))
        self.assertFalse(rules.blocks(b.SRC_PM, b.INFO, "RegQueryValue HKCU\\Software", "explorer.exe"))
        self.assertFalse(rules.blocks(b.SRC_PROC, b.INFO, "Started chrome.exe (PID 7)", "chrome.exe"))

    def test_the_log_limit_fits_under_a_thirty_million_byte_upload(self):
        self.assertEqual(b.DEFAULT_LOG_MB, 28)
        rules = b.Exclusions()
        self.assertEqual(rules.log_bytes(), 28 * 1024 * 1024)
        self.assertLess(rules.log_bytes(), 30000000)

    def test_log_bytes_counts_the_windows_line_ending(self):
        saved = b.LINE_END_EXTRA
        try:
            b.LINE_END_EXTRA = 0
            self.assertEqual(b.log_bytes("a\nb\nc\n"), 6)
            b.LINE_END_EXTRA = 1
            self.assertEqual(b.log_bytes("a\nb\nc\n"), 9)
            self.assertEqual(b.log_bytes("no newline"), 10)
        finally:
            b.LINE_END_EXTRA = saved

    def test_the_finished_log_stays_under_the_limit_with_crlf_endings(self):
        folder = tempfile.mkdtemp(prefix="bastard_crlf_")
        saved = (b.LOG_NEWLINE, b.LINE_END_EXTRA)
        try:
            b.LOG_NEWLINE = "\r\n"
            b.LINE_END_EXTRA = 1
            path = os.path.join(folder, "trace.log")
            limit = 2 * 1024 * 1024
            writer = b.LogWriter(path, ["header"], limit)
            self.assertTrue(writer.start())
            text = "RegQueryValue HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Thing"
            for index in range(40000):
                writer.put(event(float(index), b.SRC_PM, "Registry", b.INFO, text,
                                 proc="explorer.exe", pid=4000))
            writer.close(["footer line %d" % index for index in range(60)], True)
            with open(path, "rb") as fh:
                raw = fh.read()
            self.assertIn(b"\r\n", raw)
            self.assertNotIn(b"\n\n\n", raw.replace(b"\r\n", b"\n"))
            self.assertTrue(writer.dropped > 0)
            self.assertLess(len(raw), limit)
            self.assertGreater(len(raw), limit // 2)
        finally:
            b.LOG_NEWLINE, b.LINE_END_EXTRA = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_defaults_leave_our_own_rows_out(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertTrue(rules.blocks(b.SRC_PROC, b.INFO, "Started powershell.exe (PID 9) by Bastard.exe (PID 1)"))
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO, "WriteFile C:\\Tools\\Bastard_20261012.log"))
        self.assertTrue(rules.blocks(b.SRC_PM, b.CHANGE, "QueryOpen C:\\x", "Bastard.exe"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.CHANGE, "[Kernel-Registry] x", "", "FileName=Bastard_1.log"))
        self.assertTrue(rules.blocks(b.SRC_FILES, b.CHANGE, "File changed: Bastard_20261012.log"))
        self.assertFalse(rules.blocks(b.SRC_PROC, b.INFO, "Started python.exe (PID 7) by python.exe (PID 1)"))
        self.assertFalse(rules.blocks(b.SRC_PROC, b.INFO, "Started powershell.exe (PID 9) by explorer.exe (PID 2)"))

    def test_a_default_rule_never_silences_our_own_notices(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        for text in ("Bastard 1.6.1 started", "Trace started", "Trace stopped after 32.0 s",
                     "ProcMon: read 1000 events",
                     "Marker 1: the wallpaper was not written in the 6 seconds after it. 4 events (Files 4)"):
            self.assertFalse(rules.blocks(b.SRC_SYSTEM, b.INFO, text), text)
        self.assertEqual(rules.blocked, 0)

    def test_the_defaults_let_the_selftest_names_through(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        work = "C:\\Temp\\%sxyz\\watched" % selftest.WORK_PREFIX
        wanted = [
            (b.SRC_FILES, b.CHANGE, "File created: %s\\x.txt" % work),
            (b.SRC_FILES, b.CHANGE, "File renamed: %s\\x.txt -> %s\\y.txt" % (work, work)),
            (b.SRC_FILES, b.CHANGE, "File deleted: %s\\y.txt" % work),
            (b.SRC_REG, b.CHANGE, "HKCU\\%s [A] 1 (0x1) -> 2 (0x2)" % selftest.KEY),
            (b.SRC_REG, b.CHANGE, "HKCU\\%s\\Sub created" % selftest.KEY),
            (b.SRC_PM, b.CHANGE, "registry RegSetValue HKCU\\%s [A]" % selftest.KEY),
        ]
        for source, level, text in wanted:
            self.assertFalse(rules.blocks(source, level, text), text)
        self.assertEqual(rules.blocked, 0)

    def test_the_selftest_holds_etw_to_the_test_files(self):
        saved = selftest.IS_WIN
        try:
            selftest.IS_WIN = True
            checks = {name: (ok, hard) for name, ok, hard, _info in selftest.check({"admin": True}, {}, 0)}
        finally:
            selftest.IS_WIN = saved
        self.assertEqual(checks["ETW saw the test files"], (False, True))
        self.assertEqual(checks["ETW saw the test key"], (False, False))
        folder = tempfile.mkdtemp(prefix="bastard_applog_")
        saved_env = os.environ.get("LOCALAPPDATA")
        try:
            os.environ["LOCALAPPDATA"] = folder
            os.makedirs(os.path.join(folder, "Bastard"))
            with open(selftest.app_log_path(), "w", encoding="utf-8") as fh:
                fh.write("a\nETW read 5 events by Stop\nb\nETW read 9 events in all\n")
            self.assertEqual(selftest.app_log_lines(("ETW read",)), ["ETW read 5 events by Stop", "ETW read 9 events in all"])
        finally:
            if saved_env is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = saved_env
            shutil.rmtree(folder, ignore_errors=True)

    def test_etw_hears_the_providers_it_names_and_knows_a_write(self):
        guids = {}
        for name, guid, _kernel in b.ETW_RAW_PROVIDERS:
            guids.setdefault(name, []).append(guid)
        self.assertEqual(guids, {"Kernel-Registry": ["{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"],
                                 "Kernel-File": ["{EDD08927-9CC4-4E65-B970-C2560FB5C289}"],
                                 "Shell-Core": ["{30336ED4-E327-447C-9DE0-51B652C86108}"],
                                 "Immersive-Shell": ["{315A8872-923E-4EA2-9889-33CD4754BF64}"]})

        class Quiet:
            admin = True

            def __init__(self, hub):
                self.hub = hub

        class Core:
            class ProviderInfo:
                def __init__(self, name, guid, level, keywords):
                    self.name = name
                    self.guid = guid
                    self.keywords = keywords

        hub = b.Hub(b.Exclusions(b.DEFAULT_EXCLUSIONS))
        source = b.EtwRawSource(Quiet(hub))
        saved_core = (b.etw_core, b.EtwGuid)
        try:
            b.etw_core, b.EtwGuid = Core, str
            providers, used = source._providers()
        finally:
            b.etw_core, b.EtwGuid = saved_core
        self.assertEqual([provider.guid for provider in providers], [guid for _n, guid, _k in b.ETW_RAW_PROVIDERS])
        self.assertEqual(used, ["Kernel-Registry", "Kernel-File", "Shell-Core", "Immersive-Shell"])
        self.assertEqual({provider.name: provider.keywords for provider in providers},
                         {"Kernel-Registry": 0x4304, "Kernel-File": 0x1C00, "Shell-Core": 0xffffffffffffffff,
                          "Immersive-Shell": 0xffffffffffffffff})
        source.own_pid = 1
        source.failures = 0
        stamp = int(time.time() * 10000000) + b.FILETIME_EPOCH
        header = {"ProcessId": 4321, "TimeStamp": stamp, "ProviderId": "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"}
        registry = dict(header, ProviderId="{70EB4F03-C1DE-4F73-A051-33D13D5413BD}")
        saved = b.OWN_TREE
        try:
            b.OWN_TREE = b.OwnTree(1)
            b.OWN_TREE.note(777, 1, time.time() - 5, "Procmon64.exe")
            source._on((30, {"EventHeader": header, "Task Name": "CREATENEWFILE", "Description": "", "Irp": "0xFF",
                             "FileName": "\\Device\\HarddiskVolume3\\Users\\me\\x.txt"}))
            source._on((16, {"EventHeader": header, "Task Name": "WRITE", "Description": "", "Irp": "0xFF",
                             "IOSize": "0x3"}))
            source._on((15, {"EventHeader": header, "Task Name": "READ", "Description": "", "Irp": "0xFF",
                             "IOSize": "0x3"}))
            source._on((16, {"EventHeader": dict(header, ProcessId=777), "Task Name": "CREATENEWFILE",
                             "Description": "", "FileName": "\\Device\\HarddiskVolume3\\t.pml"}))
            source._on((5, {"EventHeader": registry, "Task Name": "MICROSOFT-WINDOWS-KERNEL-REGISTRY",
                            "Description": "", "KeyObject": "0xFF", "ValueName": "WallPaper"}))
            source._on((1, {"EventHeader": registry, "Task Name": "MICROSOFT-WINDOWS-KERNEL-REGISTRY",
                            "Description": "", "Disposition": "2",
                            "RelativeName": "\\REGISTRY\\USER\\S-1-5-21-1\\Software\\X"}))
            source._on((1, {"EventHeader": registry, "Task Name": "MICROSOFT-WINDOWS-KERNEL-REGISTRY",
                            "Description": "", "Disposition": "1",
                            "RelativeName": "\\REGISTRY\\USER\\S-1-5-21-1\\Software\\New"}))
            source._on((7, {"EventHeader": registry, "Task Name": "MICROSOFT-WINDOWS-KERNEL-REGISTRY",
                            "Description": "", "KeyObject": "0xFF", "ValueName": "WallPaper"}))
            source._on((27, {"EventHeader": header, "Task Name": "RENAMEPATH", "Description": "",
                             "FilePath": "\\Device\\HarddiskVolume3\\Users\\me\\renamed.jpg"}))
            source._on((12, {"EventHeader": header, "Task Name": "CREATE", "Description": "",
                             "CreateOptions": "0x05000060", "FileName": "\\Device\\HarddiskVolume3\\Users\\me\\over.jpg"}))
            source._on((12, {"EventHeader": header, "Task Name": "CREATE", "Description": "",
                             "CreateOptions": "0x01000060", "FileName": "\\Device\\HarddiskVolume3\\Users\\me\\open.dll"}))
        finally:
            b.OWN_TREE = saved
        seen = []
        while True:
            try:
                seen.append(hub.ui.get_nowait())
            except queue.Empty:
                break
        self.assertEqual([ev.level for ev in seen], [b.CHANGE] * 5)
        self.assertIn("x.txt", seen[0].text)
        self.assertIn("WallPaper", seen[1].text)
        self.assertIn("New", seen[2].text)
        self.assertIn("renamed.jpg", seen[3].text)
        self.assertIn("over.jpg", seen[4].text)
        self.assertNotIn("t.pml", " ".join(ev.text for ev in seen))

    def test_etw_asks_windows_only_for_the_changes(self):
        registry = {"SetSecurityKey": 0x4, "SetValueKey": 0x100, "DeleteValueKey": 0x200, "DeleteKey": 0x4000}
        files = {"KERNEL_FILE_KEYWORD_DELETE_PATH": 0x400, "KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH": 0x800,
                 "KERNEL_FILE_KEYWORD_CREATE_NEW_FILE": 0x1000}
        self.assertEqual(b.ETW_KEYWORDS["Kernel-Registry"], sum(registry.values()))
        self.assertEqual(b.ETW_KEYWORDS["Kernel-File"], sum(files.values()))
        for left_out in (0x1000, 0x2000, 0x400, 0x40):
            self.assertFalse(b.ETW_KEYWORDS["Kernel-Registry"] & left_out, hex(left_out))
        for left_out in (0x10, 0x20, 0x40, 0x80, 0x100, 0x200):
            self.assertFalse(b.ETW_KEYWORDS["Kernel-File"] & left_out, hex(left_out))

    def test_etw_writes_what_it_read_into_the_app_log(self):
        class Job:
            def stop(self):
                return None

        hub = b.Hub()
        source = b.EtwRawSource(FakeSession(hub))
        source.own_pid = -1
        moment = time.time() - 3
        source._on((5, {"EventHeader": {"ProcessId": 4321, "TimeStamp": filetime(moment)},
                        "ProviderName": "Kernel-Registry", "ValueName": "WallPaper"}))
        source._on("not an event")
        self.assertEqual(source.read, 2)
        self.assertAlmostEqual(source.newest, moment, delta=0.01)
        source.job = Job()
        with self.assertLogs("bastard", "INFO") as logs:
            source.finish()
        wanted = "ETW read 2 events, the newest from %s" % b.clock(source.newest)
        self.assertTrue(any(wanted + " by Stop" in line for line in logs.output), logs.output)
        self.assertTrue(any(wanted + " in all, and took" in line for line in logs.output), logs.output)

    def test_etw_says_it_needs_administrator_when_windows_refuses_it(self):
        class Refused(OSError):
            winerror = 5

        class Core:
            class ProviderInfo:
                def __init__(self, name, guid, level, keywords):
                    self.name = name

            class TraceProperties:
                pass

            class ETW:
                def __init__(self, **_options):
                    pass

                def control_stop(self, _properties):
                    return None

                def start(self):
                    raise Refused("Access is denied.")

        found = []
        for admin in (False, True):
            hub = b.Hub()
            session = FakeSession(hub)
            session.admin = admin
            source = b.EtwRawSource(session)
            saved = (b.etw_core, b.EtwGuid)
            try:
                b.etw_core, b.EtwGuid = Core, str
                source._run()
            finally:
                b.etw_core, b.EtwGuid = saved
            notes = [(ev.text, ev.level) for ev in drained(hub) if ev.source == b.SRC_SYSTEM]
            found.append((hub.snapshot()[0][b.SRC_ETW], notes))
        self.assertEqual(found[0], (("off", "needs administrator"), [("ETW: needs Bastard to run as administrator", b.WARN)]))
        self.assertEqual(found[1], (("failed", "Access is denied."),
                                    [("ETW: the ETW session could not start: Access is denied.", b.ERROR)]))

    def test_the_administrator_notices_name_all_of_etw(self):
        with io.open(SOURCE, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("kernel ETW", text)
        self.assertIn('"ETW and Trace Tools are off"', text)
        self.assertIn('"ETW and Trace Tools need administrator rights.', text)

    def test_the_closing_system_lines_still_reach_a_full_log(self):
        folder = tempfile.mkdtemp(prefix="bastard_close_")
        try:
            path = os.path.join(folder, "trace.log")
            limit = 200 * 1024
            writer = b.LogWriter(path, ["header"], limit)
            self.assertTrue(writer.start())
            now = time.time()
            for index in range(3000):
                writer.put(event(now + index * 0.001, b.SRC_PM, b.KIND_FILE, b.INFO, "ReadFile C:\\data\\%05d.bin" % index))
            self.assertTrue(writer.flush(30.0))
            self.assertTrue(writer.capped)
            writer.put(event(now + 10, b.SRC_PM, b.KIND_FILE, b.INFO, "ReadFile C:\\data\\after.bin"))
            writer.put(event(now + 11, b.SRC_SYSTEM, b.KIND_SYS, b.INFO, "ProcMon: read 1802554 events, listed 3000 of 3000"))
            writer.put(event(now + 12, b.SRC_SYSTEM, b.KIND_MARK, b.MARK,
                             "Marker 1: ProcMon listed 40 events in the 6 seconds after it"))
            writer.put(event(now + 13, b.SRC_SYSTEM, b.KIND_SYS, b.INFO, "Trace stopped after 32 seconds"))
            writer.close(["Summary"], True)
            with open(path, "r", encoding="utf-8") as fh:
                body = fh.read()
            for text in ("ProcMon: read 1802554 events", "Marker 1: ProcMon listed 40 events", "Trace stopped after 32 seconds"):
                self.assertIn(text, body)
            self.assertNotIn("after.bin", body)
            self.assertLess(os.path.getsize(path), limit)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_marker_summaries_do_not_crowd_out_the_closing_lines(self):
        folder = tempfile.mkdtemp(prefix="bastard_marks_")
        try:
            path = os.path.join(folder, "trace.log")
            limit = 200 * 1024
            writer = b.LogWriter(path, ["header"], limit)
            self.assertTrue(writer.start())
            now = time.time()
            for index in range(3000):
                writer.put(event(now + index * 0.001, b.SRC_PM, b.KIND_FILE, b.INFO, "ReadFile C:\\data\\%05d.bin" % index))
            self.assertTrue(writer.flush(30.0))
            self.assertTrue(writer.capped)
            detail = "\n".join("12:00:%02d.000  Files      File changed: C:\\Users\\me\\%s.txt" % (index, "x" * 80)
                               for index in range(60))
            for number in range(1, 21):
                summary = event(now + 20 + number, b.SRC_SYSTEM, b.KIND_MARK, b.MARK,
                                "Marker %d: the wallpaper was not written in the 6 seconds after it. 60 events (Files 60)" % number)
                summary.detail = detail
                writer.put(summary)
            writer.put(event(now + 50, b.SRC_SYSTEM, b.KIND_SYS, b.INFO, "Trace stopped after 32 seconds"))
            writer.close(["Summary"], True)
            with open(path, "r", encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("Trace stopped after 32 seconds", body)
            self.assertNotIn("(Files 60)", body)
            self.assertLess(os.path.getsize(path), limit)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_rows_from_a_finished_trace_stay_out_of_the_next_one(self):
        hub = b.Hub(b.Exclusions([]))
        hub.reset(b.SOURCE_NAMES)
        old = b.EtwRawSource(FakeSession(hub))
        self.assertIsNotNone(old.emit(b.KIND_ETW, "row of the first trace"))
        hub.closed = True
        hub.reset(b.SOURCE_NAMES)
        drained(hub)
        new = b.EtwRawSource(FakeSession(hub))
        self.assertIsNone(old.emit(b.KIND_ETW, "late row of the first trace"))
        self.assertIsNone(old.note("late note of the first trace"))
        old.status("failed", "late")
        self.assertIsNotNone(new.emit(b.KIND_ETW, "row of the second trace"))
        status, counts = hub.snapshot()
        self.assertEqual(status[b.SRC_ETW], ("idle", ""))
        self.assertEqual(counts, {b.SRC_ETW: 1})
        self.assertEqual([ev.text for ev in drained(hub)], ["row of the second trace"])
        self.assertEqual(hub.late, 0)

    def test_closing_during_a_trace_closes_procmon_first(self):
        class Recorder(b.Source):
            def __init__(self, session, name, order):
                b.Source.__init__(self, session)
                self.name = name
                self.order = order

            def finish(self):
                self.order.append(self.name)

        folder = tempfile.mkdtemp(prefix="bastard_close_order_")
        saved = b.PROGRAM_DIR
        others = [name for name in b.SOURCE_NAMES if name != b.SRC_PM]
        try:
            b.PROGRAM_DIR = folder
            for abort, first in ((True, b.SRC_PM), (False, b.SOURCE_NAMES[0])):
                order = []
                session = b.Session(b.Hub(b.Exclusions([])), b.parse_options([]))
                session.sources = [Recorder(session, name, order) for name in b.SOURCE_NAMES]
                if abort:
                    session.abort_event.set()
                session.request_stop()
                session.finish()
                self.assertEqual(order[0], first, order)
                self.assertEqual([name for name in order if name != b.SRC_PM], others)
                self.assertEqual(sorted(order), sorted(b.SOURCE_NAMES))
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_registry_rights_names(self):
        self.assertEqual(b.reg_rights_name(0xF003F), "FullControl")
        self.assertEqual(b.reg_rights_name(0x10000000), "FullControl")
        self.assertEqual(b.reg_rights_name(0x2001F), "ReadKey, WriteKey")
        self.assertEqual(b.reg_rights_name(0x20019), "ReadKey")
        self.assertEqual(b.reg_rights_name(0x20006), "WriteKey")
        self.assertEqual(b.reg_rights_name(0x1), "QueryValues")
        self.assertEqual(b.reg_rights_name(0x4), "0x4")

    def test_acl_lines_read_the_rights_list(self):
        class Dacl:
            def __init__(self, aces):
                self.aces = aces

            def GetAceCount(self):
                return len(self.aces)

            def GetAce(self, index):
                return self.aces[index]

        class Fake:
            SE_REGISTRY_KEY = 4
            DACL_SECURITY_INFORMATION = 4

            @staticmethod
            def LookupAccountSid(_server, sid):
                if sid == "sid-user":
                    return ("Clementine", "CLEMENTINE", 1)
                raise OSError("no mapping")

            @staticmethod
            def ConvertSidToStringSid(sid):
                return "S-1-15-3-1024"

        saved = b.win32security
        try:
            b.win32security = Fake
            dacl = Dacl([((b.ACE_ALLOWED, 0), 0xF003F, "sid-user"),
                         ((b.ACE_DENIED, 0), 0x20006, "sid-user"),
                         ((b.ACE_ALLOWED, 0), 0x20019, "sid-app"),
                         ((5, 0), 0xF003F, "sid-user")])
            self.assertEqual(b.acl_lines(dacl), [
                ("Allow CLEMENTINE\\Clementine FullControl", False),
                ("Deny CLEMENTINE\\Clementine WriteKey", True),
                ("Allow S-1-15-3-1024 ReadKey", False),
            ])
        finally:
            b.win32security = saved

    def test_the_acl_probe_asks_for_nothing_it_may_write(self):
        with io.open(SOURCE, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("Get-Acl", text)
        self.assertNotIn("REGISTRY_ACL_SCRIPT", text)
        self.assertIn("DACL_SECURITY_INFORMATION", text)
        self.assertIn("OWNER_SECURITY_INFORMATION", text)
        self.assertNotIn("SACL_SECURITY_INFORMATION", text)
        self.assertEqual(text.count("GetNamedSecurityInfo"), 2)
        self.assertEqual(b.REGISTRY_ACL_OBJECT, "CURRENT_USER\\Control Panel\\Desktop")
        self.assertEqual(text.lower().count("powershell"), 1)

    def test_our_own_process_tree(self):
        tree = b.OwnTree(100)
        tree.note(200, 100)
        tree.note(300, 200)
        tree.note(400, 999)
        tree.note(500, 0)
        for pid, want in ((100, True), (200, True), (300, True), (400, False), (500, False), (0, False)):
            self.assertEqual(tree.holds(pid), want, pid)
        tree.reset(100)
        self.assertFalse(tree.holds(200))
        self.assertTrue(tree.holds(100))

    def test_a_pid_our_helper_left_behind_is_not_ours(self):
        class Fake(b.ProcessSource):
            def __init__(self):
                self.seen = []

            def emit(self, kind, text, level=b.INFO, pid=None, proc="", detail="", ts=None):
                self.seen.append(text)

        saved = b.OWN_TREE
        try:
            b.OWN_TREE = b.OwnTree(100)
            source = Fake()
            source._emit_start(4321, 100, "sc.exe", "", 1000.0, "")
            source._emit_exit(4321, "sc.exe", 0, 0.2, 1000.2)
            source._emit_start(4321, 640, "Photos.exe", "", 1005.0, "")
            source._emit_exit(4321, "Photos.exe", 0, 3.0, 1008.0)
            self.assertEqual(len(source.seen), 2, source.seen)
            self.assertTrue(source.seen[0].startswith("Started Photos.exe (PID 4321)"), source.seen)
            digest = b.ProcmonDigest(100, 100)
            digest.add(1000.1, "sc.exe", 4321, "RegQueryValue", "HKLM\\X", "SUCCESS")
            digest.add(1006.0, "Photos.exe", 4321, "RegSetValue", "HKCU\\Control Panel\\Desktop", "ACCESS DENIED")
            self.assertEqual((digest.ours, len(digest.rows)), (1, 1))
            self.assertEqual(digest.rows[0][1], "Photos.exe")
            b.OWN_TREE = b.OwnTree(100)
            source = Fake()
            source._emit_start(4321, 100, "wevtutil.exe", "", 2000.0, "")
            source._emit_exit(4321, "wevtutil.exe", 0, 0.2, 2000.2)
            source._emit_start(4321, 640, "Photos.exe", "", 2000.5, "")
            self.assertTrue(source.seen[-1].startswith("Started Photos.exe (PID 4321)"), source.seen)
            digest = b.ProcmonDigest(100, 100)
            digest.add(2000.6, "Photos.exe", 4321, "RegSetValue", "HKCU\\Control Panel\\Desktop", "ACCESS DENIED")
            self.assertEqual((digest.ours, len(digest.rows)), (0, 1))
        finally:
            b.OWN_TREE = saved

    def test_the_digest_skips_our_own_processes(self):
        saved = b.OWN_TREE
        try:
            b.OWN_TREE = b.OwnTree(7)
            b.OWN_TREE.note(8, 7)
            digest = b.ProcmonDigest(7, 100)
            digest.add("t", "Bastard.exe", 7, "RegQueryValue", "HKCU\\a", "SUCCESS")
            digest.add("t", "powershell.exe", 8, "RegSetValue", "HKCU\\b", "SUCCESS")
            digest.add("t", "explorer.exe", 9, "RegSetValue", "HKCU\\c", "SUCCESS")
            self.assertEqual(digest.total, 3)
            self.assertEqual(digest.ours, 2)
            self.assertEqual(len(digest.rows), 1)
            self.assertEqual(digest.reg_writes, 1)
        finally:
            b.OWN_TREE = saved

    def test_the_defaults_leave_the_registry_handle_rows_out(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        for op in ("RegOpenKey", "RegCloseKey", "RegQueryKey", "RegEnumKey", "RegEnumValue", "RegSetInfoKey"):
            self.assertTrue(rules.blocks(b.SRC_PM, b.INFO, "%s HKCU\\Control Panel\\Desktop" % op), op)
            self.assertFalse(rules.blocks(b.SRC_PM, b.ERROR, "%s HKLM\\x: ACCESS DENIED" % op), op)
        for op in ("RegQueryValue", "RegCreateKey"):
            self.assertFalse(rules.blocks(b.SRC_PM, b.INFO, "%s HKCU\\Control Panel\\Desktop" % op), op)
        self.assertFalse(rules.blocks(b.SRC_PM, b.CHANGE, "RegSetValue HKCU\\Control Panel\\Desktop [Wallpaper]"))
        self.assertFalse(rules.blocks(b.SRC_REG, b.INFO, "RegOpenKey HKCU\\Control Panel\\Desktop"))

    def test_the_colour_rule_names_the_path_the_rows_carry(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        real = "RegQueryValue HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\\ColorPrevalence"
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO, real))
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO,
                                     "RegQueryValue HKCU\\SOFTWARE\\Microsoft\\Windows\\DWM\\ColorPrevalence"))
        self.assertFalse(rules.blocks(b.SRC_PM, b.CHANGE, real.replace("Query", "Set")))

    def test_the_filter_rows_above_the_list_are_gone(self):
        for name in ("CHIP_SOURCES", "CHIP_KINDS", "Chip"):
            self.assertFalse(hasattr(b, name), name)
        with io.open(SOURCE, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("kind_chips", text)
        self.assertNotIn("source_chips", text)

    def test_the_processes_source_leaves_our_own_helpers_out(self):
        class Fake(b.ProcessSource):
            def __init__(self):
                self.seen = []

            def emit(self, kind, text, level=b.INFO, pid=None, proc="", detail="", ts=None):
                self.seen.append(text)
                return text

        saved = b.OWN_TREE
        try:
            b.OWN_TREE = b.OwnTree(100)
            source = Fake()
            source._emit_start(200, 100, "powershell.exe", "", 1.0, "")
            source._emit_start(300, 200, "conhost.exe", "", 1.0, "")
            source._emit_start(900, 4, "explorer.exe", "", 1.0, "")
            source._emit_exit(300, "conhost.exe", 0, 0.1, 2.0)
            source._emit_exit(900, "explorer.exe", 0, 5.0, 2.0)
            self.assertEqual(len(source.seen), 2)
            self.assertTrue(source.seen[0].startswith("Started explorer.exe (PID 900)"), source.seen)
            self.assertTrue(source.seen[1].startswith("Exited explorer.exe (PID 900)"), source.seen)
            for text in source.seen:
                self.assertNotIn("powershell", text)
                self.assertNotIn("conhost", text)
            self.assertTrue(b.OWN_TREE.holds(200))
            self.assertTrue(b.OWN_TREE.holds(300, 1.5))
            self.assertFalse(b.OWN_TREE.holds(300))
            self.assertFalse(b.OWN_TREE.holds(900))
        finally:
            b.OWN_TREE = saved

    def test_marker_summary(self):
        text, level, _ = b.marker_summary(2, 100.0, [event(99.0), event(107.0)])
        self.assertEqual(level, b.WARN)
        self.assertEqual(text, "Marker 2: nothing happened in the 6 seconds after it")
        events = [event(101.0, proc="Photos.exe"), event(102.0, "Registry", "Registry", proc="Photos.exe"),
                  event(103.0, "System", "System"), event(105.9, proc="x.exe")]
        text, level, detail = b.marker_summary(1, 100.0, events)
        self.assertEqual(level, b.MARK)
        self.assertEqual(text, "Marker 1: the wallpaper was not written in the 6 seconds after it. 3 events (Files 2, Registry 1), "
                               "from Photos.exe, x.exe")
        self.assertEqual(len(detail.splitlines()), 5)
        self.assertTrue(detail.startswith("Bastard saw no write to TranscodedWallpaper"), detail)

    def test_a_marker_summary_says_when_the_wallpaper_was_written(self):
        events = [event(101.0, text="File changed: C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper"),
                  event(101.5, "Registry", "Registry", text="HKCU\\Control Panel\\Desktop [WallPaper]: a.jpg -> b.jpg"),
                  event(102.0, "ProcMon", "Registry", text="RegSetValue HKCU\\Control Panel\\Desktop\\WallPaper",
                        proc="explorer.exe"),
                  event(102.5, "Wallpaper", "Desktop", text="Wallpaper changed: a.jpg -> b.jpg"),
                  event(103.0, "Registry", "Registry", text="HKCU\\Control Panel\\Desktop [CursorBlinkRate]: 530 -> 500")]
        text, level, detail = b.marker_summary(1, 100.0, events)
        self.assertEqual(level, b.MARK)
        self.assertEqual(text, "Marker 1: the wallpaper was written in the 6 seconds after it (explorer.exe). "
                               "5 events (Registry 2, Files 1, ProcMon 1, Wallpaper 1), from explorer.exe")
        self.assertTrue(detail.startswith("Something wrote the wallpaper in these 6 seconds."), detail)

    def test_a_marker_summary_counts_refused_access(self):
        events = [event(101.0, "ProcMon", "File", b.ERROR, "CreateFile C:\\Users\\me\\Pictures\\a.jpg: ACCESS DENIED",
                        proc="Photos.exe"),
                  event(101.2, "ETW", "File", b.ERROR, "[Kernel-File] Status=0xC0000022", proc="RuntimeBroker.exe"),
                  event(101.4, "ProcMon", "Registry", b.ERROR, "RegOpenKey HKLM\\X: PRIVILEGE NOT HELD", proc="Photos.exe"),
                  event(101.6, "Event Log", "Log", b.ERROR, "Application Error 1000 in Photos.exe"),
                  event(101.8, "Files", "File", b.CHANGE, "File created: C:\\Users\\me\\AppData\\Local\\Packages\\x\\a.jpg")]
        text, level, _detail = b.marker_summary(3, 100.0, events)
        self.assertEqual(level, b.MARK)
        self.assertEqual(text, "Marker 3: the wallpaper was not written in the 6 seconds after it, and access was refused 3 times "
                               "(Photos.exe, RuntimeBroker.exe). 5 events (ProcMon 2, ETW 1, Event Log 1, Files 1), "
                               "from Photos.exe, RuntimeBroker.exe")

    def test_wallpaper_writes_are_told_apart_from_other_rows(self):
        cases = [
            (b.SRC_FILES, b.CHANGE, "File changed: C:\\U\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper", True),
            (b.SRC_FILES, b.CHANGE, "File created: C:\\U\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\CachedFiles\\c.jpg", True),
            (b.SRC_FILES, b.CHANGE, "File created: C:\\U\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\Bastard_check.tmp", False),
            (b.SRC_FILES, b.INFO, "File changed: C:\\U\\Themes\\TranscodedWallpaper", False),
            (b.SRC_REG, b.CHANGE, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers [BackgroundType]: 0 -> 2", True),
            (b.SRC_REG, b.CHANGE, "HKCU\\Control Panel\\Desktop [TranscodedImageCache]: <binary 3 KB> -> <binary 3 KB>", True),
            (b.SRC_REG, b.CHANGE, "HKCU\\Control Panel\\Desktop [WheelScrollLines]: 3 -> 5", False),
            (b.SRC_WMI, b.CHANGE, "WMI change: HKEY_USERS\\S-1-5-21-1\\Control Panel\\Desktop [WallPaper]", True),
            (b.SRC_WALL, b.CHANGE, "Wallpaper changed: a.jpg -> b.jpg", True),
            (b.SRC_WALL, b.INFO, "Wallpaper at start: a.jpg", False),
            (b.SRC_ETW, b.CHANGE, "[Kernel-Registry] KeyName=\\REGISTRY\\USER\\S-1\\Control Panel\\Desktop | ValueName=WallPaper", True),
        ]
        for source, level, text, wanted in cases:
            self.assertEqual(b.wallpaper_write(source, level, text), wanted, text)

    def test_procmon_marker_lines_count_wallpaper_writes_and_refusals(self):
        hub = b.Hub()
        source = QuietProcMon(hub)
        start = time.time()
        source.session.markers = [(1, start), (2, start + 30)]
        digest = b.ProcmonDigest(1, 1000)
        digest.add(start + 1, "explorer.exe", OTHER_PID, "RegSetValue", "HKCU\\Control Panel\\Desktop\\WallPaper", "SUCCESS")
        digest.add(start + 2, "explorer.exe", OTHER_PID, "WriteFile",
                   "C:\\U\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper", "SUCCESS")
        digest.add(start + 3, "Photos.exe", OTHER_PID, "CreateFile", "C:\\U\\Pictures\\a.jpg", "ACCESS DENIED")
        digest.add(start + 31, "Photos.exe", OTHER_PID, "CreateFile", "C:\\U\\Pictures\\b.jpg", "ACCESS DENIED")
        source._publish(digest, "4 events")
        marks = [ev.text for ev in drained(hub) if ev.kind == b.KIND_MARK]
        self.assertEqual(marks, ["Marker 1: ProcMon listed 3 events in the 6 seconds after it, of which 2 wrote the "
                                 "wallpaper and 1 was refused access",
                                 "Marker 2: ProcMon listed 1 event in the 6 seconds after it, of which 1 was refused access"])

    def test_hub(self):
        hub = b.Hub()
        ev = hub.emit("Files", "File", "a\x00b", ts=603246995523.0)
        self.assertEqual(ev.text, "ab")
        self.assertLess(abs(ev.ts - time.time()), 5)
        hub.set_status("Files", "running", "1 folder")
        status, counts = hub.snapshot()
        self.assertEqual(status["Files"], ("running", "1 folder"))
        self.assertEqual(counts["Files"], 1)
        hub.reset(["Files"])
        self.assertEqual(hub.snapshot(), ({"Files": ("idle", "")}, {}))

    def test_a_repeated_row_is_listed_once_with_its_count(self):
        hub = b.Hub()
        now = time.time()
        first = hub.emit(b.SRC_PM, b.KIND_REG, "RegQueryValue HKCU\\A", pid=5, proc="x.exe", detail="Path: A", ts=now)
        for step in (1, 2):
            self.assertIs(hub.emit(b.SRC_PM, b.KIND_REG, "RegQueryValue HKCU\\A", pid=5, proc="x.exe",
                                   detail="Path: A", ts=now + step), first)
        self.assertEqual(drained(hub), [first])
        self.assertEqual((first.ts, first.count, first.times), (now, 3, [now + 1, now + 2]))
        self.assertEqual(first.headline(), "RegQueryValue HKCU\\A (3 times)")
        self.assertEqual(hub.snapshot()[1], {b.SRC_PM: 3})
        self.assertEqual(hub.take_bumped(), {first})
        self.assertEqual(hub.take_bumped(), set())
        self.assertEqual(b.repeat_suffix(1), "")

    def test_only_a_row_the_same_in_every_part_is_a_repeat(self):
        hub = b.Hub()
        now = time.time()
        base = dict(kind=b.KIND_REG, text="RegQueryValue HKCU\\A", level=b.INFO, pid=5, proc="x.exe",
                    detail="Path: A")
        hub.emit(b.SRC_PM, ts=now, **base)
        for change in (dict(kind=b.KIND_FILE), dict(text="RegQueryValue HKCU\\B"), dict(level=b.ERROR), dict(pid=6),
                       dict(proc="y.exe"), dict(detail="Path: B")):
            hub.emit(b.SRC_PM, ts=now, **dict(base, **change))
        hub.emit(b.SRC_ETW, ts=now, **base)
        self.assertEqual(len(drained(hub)), 8)
        hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "ETW: watching 4 providers", ts=now)
        hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "ETW: watching 4 providers", ts=now)
        self.assertEqual(len(drained(hub)), 2)

    def test_repeats_are_counted_again_after_a_marker_and_after_clear(self):
        hub = b.Hub()
        now = time.time() - 60
        rows = []
        for ts in (now, now + 1, now + 20, now + 21, now + 2):
            rows.append(hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=ts))
            if ts == now + 1:
                hub.mark(now + 10)
        self.assertEqual([ev.seq for ev in rows], [rows[0].seq] * 2 + [rows[2].seq] * 2 + [rows[0].seq])
        self.assertEqual((rows[0].count, rows[2].count, rows[2].ts), (3, 2, now + 20))
        hub.split()
        again = hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=now + 22)
        self.assertNotIn(again, rows)
        hub.reset([b.SRC_FILES])
        self.assertEqual((hub.repeats, hub.marks, hub.bumped), ({}, [], set()))

    def test_the_hub_counts_repeats_for_no_more_rows_than_the_list_can_hold(self):
        saved = b.STORE_LIMIT
        try:
            b.STORE_LIMIT = 3
            hub = b.Hub()
            now = time.time()
            rows = [hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: %d.txt" % index, b.CHANGE, ts=now + index)
                    for index in range(5)]
            self.assertLessEqual(len(hub.repeats), 3)
            self.assertIs(hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: 4.txt", b.CHANGE, ts=now + 6), rows[4])
            again = hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: 0.txt", b.CHANGE, ts=now + 7)
            self.assertIsNot(again, rows[0])
            self.assertEqual((rows[0].count, rows[4].count, again.count), (1, 2, 1))
        finally:
            b.STORE_LIMIT = saved

    def test_the_trace_log_shows_a_repeat_once_at_its_first_time(self):
        folder = tempfile.mkdtemp()
        try:
            for rewrite in (True, False):
                path = os.path.join(folder, "t%d.log" % rewrite)
                hub = b.Hub()
                writer = b.LogWriter(path, ["Header"])
                self.assertTrue(writer.start())
                hub.writer = writer
                now = time.time()
                for step in range(12):
                    hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=now + step)
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File created: x.txt", b.CHANGE, ts=now + 5)
                writer.close(["Summary"], rewrite)
                with open(path, encoding="utf-8") as fh:
                    lines = [line for line in fh.read().splitlines() if " Files " in line]
                self.assertEqual(len(lines), 2, lines)
                self.assertTrue(lines[0].startswith(b.stamp(now)), lines[0])
                self.assertTrue(lines[0].endswith("File changed: tick.txt (12 times)"), lines[0])
                self.assertTrue(lines[1].endswith("File created: x.txt"), lines[1])
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_log_limit_counts_what_the_count_adds(self):
        folder = tempfile.mkdtemp()
        try:
            hub = b.Hub()
            writer = b.LogWriter(os.path.join(folder, "t.log"), ["Header"])
            self.assertTrue(writer.start())
            hub.writer = writer
            now = time.time()
            hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=now)
            self.assertTrue(writer.flush(5.0))
            before = writer.written
            for step in range(1, 100):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=now + step)
            self.assertTrue(writer.flush(5.0))
            self.assertEqual(writer.written - before, len(b.repeat_suffix(100)))
            writer.close([], True)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_footer_counts_every_repeat_the_log_left_out(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "t.log")
            hub = b.Hub()
            writer = b.LogWriter(path, ["Header"], b.LOG_FOOTER_ROOM + 2000)
            self.assertTrue(writer.start())
            hub.writer = writer
            now = time.time()
            for index in range(40):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: %02d %s" % (index, "x" * 80), b.CHANGE, ts=now)
            self.assertTrue(writer.flush(5.0))
            self.assertTrue(writer.capped)
            late = hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: late.txt", b.CHANGE, ts=now + 1)
            for step in range(4):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: late.txt", b.CHANGE, ts=now + 2 + step)
            self.assertEqual(late.count, 5)
            writer.close(["Summary"], True)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("late.txt", text)
            self.assertIn("%d later events left out" % (writer.dropped + 4), text)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_footer_still_counts_every_repeat_without_holding_every_row_left_out(self):
        folder = tempfile.mkdtemp()
        saved = b.STORE_LIMIT
        try:
            b.STORE_LIMIT = 5
            path = os.path.join(folder, "t.log")
            hub = b.Hub()
            writer = b.LogWriter(path, ["Header"], b.LOG_FOOTER_ROOM + 2000)
            self.assertTrue(writer.start())
            hub.writer = writer
            now = time.time()
            for index in range(60):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: %02d %s" % (index, "x" * 80), b.CHANGE, ts=now)
            for step in range(3):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: 59 %s" % ("x" * 80), b.CHANGE, ts=now + 1 + step)
            self.assertTrue(writer.flush(5.0))
            self.assertTrue(writer.capped)
            self.assertGreater(writer.dropped, 5)
            self.assertLessEqual(len(writer.left), 5)
            writer.close(["Summary"], True)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("%d later events left out" % (writer.dropped + 3), text)
        finally:
            b.STORE_LIMIT = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_repeats_after_the_log_is_full_never_crowd_out_the_closing_lines(self):
        folder = tempfile.mkdtemp(prefix="bastard_full_")
        try:
            path = os.path.join(folder, "trace.log")
            limit = 200 * 1024
            hub = b.Hub()
            writer = b.LogWriter(path, ["header"], limit)
            self.assertTrue(writer.start())
            hub.writer = writer
            now = time.time()
            for index in range(3000):
                hub.emit(b.SRC_PM, b.KIND_FILE, "ReadFile C:\\data\\%05d.bin" % index, ts=now + index * 0.001)
            self.assertTrue(writer.flush(30.0))
            self.assertTrue(writer.capped)
            for ev in list(writer.events):
                hub.emit(b.SRC_PM, b.KIND_FILE, ev.text, ts=ev.ts + 5)
            for index in range(4000):
                for step in range(2):
                    hub.emit(b.SRC_PM, b.KIND_FILE, "RegQueryValue HKLM\\late\\%05d" % index, ts=now + 6 + step)
            hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "ProcMon: read 1802554 events, listed 11000 of 11000", ts=now + 11)
            hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "Trace stopped after 32 seconds", ts=now + 13)
            writer.close(["Summary"], True)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for line in ("ProcMon: read 1802554 events", "Trace stopped after 32 seconds", "11000 later events left out"):
                self.assertIn(line, text)
            self.assertNotIn("times)", text)
            self.assertLess(os.path.getsize(path), limit)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_marker_summary_counts_the_repeats_inside_its_six_seconds(self):
        ev = event(101.0, text="RegQueryValue HKCU\\A", proc="x.exe")
        for ts in (102.0, 105.0, 107.0, 120.0):
            ev.repeat(ts)
        text, level, detail = b.marker_summary(1, 100.0, [ev])
        self.assertEqual(level, b.MARK)
        self.assertEqual(text, "Marker 1: the wallpaper was not written in the 6 seconds after it. 3 events (Files 3), from x.exe")
        self.assertTrue(detail.endswith("RegQueryValue HKCU\\A (3 times)"), detail)
        self.assertEqual(ev.seen_between(106.0, 130.0), 2)

    def test_the_marker_summary_at_stop_counts_every_repeat_after_the_marker(self):
        folder = tempfile.mkdtemp(prefix="bastard_repeat_")
        saved = b.PROGRAM_DIR
        try:
            b.PROGRAM_DIR = folder
            hub = b.Hub()
            session = b.Session(hub, b.parse_options([]))
            session.sources = []
            session.writer = b.LogWriter(session.log_path, session.header())
            self.assertTrue(session.writer.start())
            hub.writer = session.writer
            start = time.time() - 30
            for index in range(5):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=start - 1 + index * 0.1)
            session.markers.append((1, start))
            hub.mark(start)
            for index in range(300):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=start + 1 + index % 5)
            for index in range(50):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick.txt", b.CHANGE, ts=start + 10)
            session.request_stop()
            session.finish()
            summary = [ev.text for ev in drained(hub) if ev.text.startswith("Marker 1:")]
            self.assertEqual(summary, ["Marker 1: the wallpaper was not written in the 6 seconds after it. 300 events (Files 300)"])
            with open(session.log_path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("File changed: tick.txt (5 times)", text)
            self.assertIn("File changed: tick.txt (350 times)", text)
            self.assertIn("Files: 355 events", text)
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_log_writer_sorts(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "t.log")
            writer = b.LogWriter(path, ["Header"])
            self.assertTrue(writer.start())
            now = time.time()
            writer.put(event(now + 2, text="second"))
            writer.put(event(now + 1, text="first"))
            writer.close(["Summary"], True)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertLess(text.index("first"), text.index("second"))
            self.assertTrue(text.startswith("Header\n"))
            self.assertTrue(text.rstrip().endswith("Summary"))
            self.assertFalse(os.path.exists(path + ".tmp"))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_exports(self):
        folder = tempfile.mkdtemp()
        try:
            events = [event(time.time(), text='quote " and comma ,', proc="a.exe", pid=3)]
            b.write_export(os.path.join(folder, "e.csv"), "csv", events)
            b.write_export(os.path.join(folder, "e.json"), "json", events)
            with open(os.path.join(folder, "e.json"), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["events"][0]["event"], 'quote " and comma ,')
            self.assertEqual(data["events"][0]["count"], 1)
            self.assertEqual(data["bastard"], b.VERSION)
            with open(os.path.join(folder, "e.csv"), encoding="utf-8-sig") as fh:
                self.assertTrue(fh.readline().startswith("Time,Source,Kind,Level,Process,PID,Event,Detail"))
            events[0].repeat(time.time())
            b.write_export(os.path.join(folder, "e.csv"), "csv", events)
            b.write_export(os.path.join(folder, "e.json"), "json", events)
            with open(os.path.join(folder, "e.csv"), encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.reader(fh))
            self.assertEqual((rows[0][-1], rows[1][-1], rows[1][6]), ("Count", "2", 'quote " and comma ,'))
            with open(os.path.join(folder, "e.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["events"][0]["count"], 2)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_options(self):
        options = b.parse_options(["--selftest", "r.json", "--watch-key", "HKCU\\X", "--seconds", "12", "--bogus"])
        self.assertTrue(options["selftest"].endswith("r.json"))
        self.assertEqual(options["watch_keys"], ["HKCU\\X"])
        self.assertEqual(options["seconds"], 12.0)
        self.assertEqual(b.duration_clock(3725), "01:02:05")

    def test_commented_rules_are_kept_through_a_save_and_a_load(self):
        folder = tempfile.mkdtemp(prefix="bastard_hash_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            lines = ["# ProcMon | | chrome.exe", "Files | change | tick.txt", "; ETW | info", "#", ";;"]
            rules = b.Exclusions(lines, 9, True, 5000)
            self.assertEqual(b.save_exclusions(rules, path), "")
            back = b.load_exclusions(path)
            self.assertEqual(back.lines, lines)
            self.assertEqual(back.rules, [("files", "change", "tick.txt", "")])
            self.assertEqual((back.enabled, back.log_mb, back.procmon_rows), (True, 9, 5000))
            self.assertEqual(b.load_exclusions(path).lines, lines)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_hand_written_filter_file_still_loads(self):
        folder = tempfile.mkdtemp(prefix="bastard_hand_")
        try:
            path = os.path.join(folder, "Exclusions.ini")
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write("; a note at the top\n# another\n[Exclusions]\n# a note in the section\nenabled = no\n"
                         "rules = Files | change | a.txt\n    ; Files | change | b.txt\n\n    Files | | c.txt\n"
                         "[Options]\nmax_log_mb = 12\n")
            back = b.load_exclusions(path)
            self.assertEqual(back.lines, ["Files | change | a.txt", "; Files | change | b.txt", "Files | | c.txt"])
            self.assertEqual((back.enabled, back.log_mb), (False, 12))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_counters_add_up_when_many_threads_count_at_once(self):
        hub = b.Hub(b.Exclusions(["Files | | noise"]))

        def send(text):
            for _index in range(3000):
                hub.emit(b.SRC_FILES, b.KIND_FILE, text)

        for text in ("noise", "late"):
            if text == "late":
                hub.closed = True
            threads = [threading.Thread(target=send, args=(text,)) for _index in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(hub.exclusions.blocked, 24000)
        self.assertEqual(hub.late, 24000)

    def test_a_check_that_only_looks_counts_nothing(self):
        rules = b.Exclusions(["Files | | noise"])
        self.assertTrue(rules.blocks(b.SRC_FILES, b.CHANGE, "noise", count=False))
        self.assertEqual(rules.blocked, 0)
        self.assertTrue(rules.blocks(b.SRC_FILES, b.CHANGE, "noise"))
        self.assertEqual(rules.blocked, 1)

    def test_the_left_out_count_starts_again_with_each_trace(self):
        hub = b.Hub(b.Exclusions(["Files | | noise"]))
        hub.emit(b.SRC_FILES, b.KIND_FILE, "noise")
        self.assertEqual(hub.exclusions.blocked, 1)
        hub.reset([b.SRC_FILES])
        self.assertEqual(hub.exclusions.blocked, 0)

    def test_the_log_writer_can_be_waited_on(self):
        folder = tempfile.mkdtemp(prefix="bastard_flush_")
        try:
            writer = b.LogWriter(os.path.join(folder, "t.log"), ["Header"])
            self.assertTrue(writer.start())
            for index in range(20000):
                writer.put(event(float(index), text="line %d" % index))
            self.assertTrue(writer.flush(30.0))
            self.assertEqual(len(writer.events), 20000)
            writer.close(["Summary"], False)
            self.assertFalse(writer.flush(1.0))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_the_marker_summary_at_stop_counts_every_event_sent_before_it(self):
        folder = tempfile.mkdtemp(prefix="bastard_stop_")
        saved = b.PROGRAM_DIR
        try:
            b.PROGRAM_DIR = folder
            hub = b.Hub()
            session = b.Session(hub, b.parse_options([]))
            session.sources = []
            session.writer = b.LogWriter(session.log_path, session.header())
            self.assertTrue(session.writer.start())
            hub.writer = session.writer
            start = time.time() - 30
            session.markers.append((1, start))
            for index in range(30000):
                hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: %d" % index, b.CHANGE, ts=start + 1 + index % 5)
            session.request_stop()
            session.finish()
            summary = [ev.text for ev in drained(hub) if ev.text.startswith("Marker 1:")]
            self.assertEqual(summary, ["Marker 1: the wallpaper was not written in the 6 seconds after it. 30000 events "
                                       "(Files 30000)"])
        finally:
            b.PROGRAM_DIR = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_only_the_newest_trace_logs_are_kept(self):
        folder = tempfile.mkdtemp(prefix="bastard_tidy_")
        try:
            names = ["Bastard_202610%02d_101010.log" % day for day in range(1, 9)]
            others = ["Bastard.log", "Bastard_notes.log", "Bastard_20261001_101010.csv", "Bastard_20261001_1010.log",
                      "notes.txt"]
            for name in names + others:
                with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
                    fh.write("x")
            self.assertEqual(b.tidy_trace_logs(folder, b.TRACE_LOG_KEEP - 1), names[:4])
            self.assertEqual(sorted(os.listdir(folder)), sorted(names[4:] + others))
            self.assertEqual(b.tidy_trace_logs(folder, b.TRACE_LOG_KEEP - 1), [])
            self.assertEqual(b.tidy_trace_logs(os.path.join(folder, "missing"), 4), [])
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class Processes(unittest.TestCase):
    def source(self):
        class Fake(b.ProcessSource):
            def __init__(self):
                self.seen = []
                self.lock = threading.Lock()
                self.known = {}
                self.reported = {}
                self.ended = {}
                self.pending = []
                self.etw = None
                self.etw_active = False
                self.etw_hits = 0
                self.etw_misses = 0
                self.tables = []
                self.session = FakeSession()

            def wait(self, _seconds):
                return not self.tables

            def emit(self, kind, text, level=b.INFO, pid=None, proc="", detail="", ts=None):
                self.seen.append(text)

        return Fake()

    def poll(self, source, *tables):
        saved = (b.process_table, b.psutil)
        source.tables = list(tables)
        try:
            b.process_table = lambda known=None: source.tables.pop(0)
            b.psutil = None
            source._poll()
        finally:
            b.process_table, b.psutil = saved
        return source.seen

    def info(self, pid, name, ctime):
        return {"pid": pid, "name": name, "ctime": ctime, "ppid": 0}

    def test_a_pid_taken_over_between_two_polls_is_reported(self):
        now = time.time()
        source = self.source()
        first = self.info(3999001, "first.exe", now - 10.0)
        source.known = {3999001: first}
        second = self.info(3999001, "second.exe", now - 2.0)
        seen = self.poll(source, {3999001: second}, {})
        self.assertEqual(len(seen), 3, seen)
        self.assertEqual(seen[0], "Exited first.exe (PID 3999001) after 8.0 s")
        self.assertEqual(seen[1], "Started second.exe (PID 3999001)")
        self.assertTrue(seen[2].startswith("Exited second.exe (PID 3999001) after"), seen)

    def test_a_pid_taken_over_soon_after_is_reported_in_full(self):
        now = time.time()
        source = self.source()
        source.known = {3999002: self.info(3999002, "first.exe", now - 3.0)}
        seen = self.poll(source, {}, {3999002: self.info(3999002, "second.exe", now - 1.0)}, {})
        self.assertEqual(len(seen), 3, seen)
        self.assertTrue(seen[0].startswith("Exited first.exe (PID 3999002)"), seen)
        self.assertEqual(seen[1], "Started second.exe (PID 3999002)")
        self.assertTrue(seen[2].startswith("Exited second.exe (PID 3999002)"), seen)

    def test_kernel_events_and_the_poll_still_report_a_process_once(self):
        now = time.time()
        source = self.source()
        source.etw_active = True
        info = self.info(3999003, "quick.exe", now - 1.0)
        source.etw_started(3999003, 0, "", now - 1.0, "")
        source._new(info, now)
        source.etw_exited(3999003, 0, "", now - 0.5)
        source._gone(info, now)
        source._flush(now + 10.0)
        self.assertEqual(len(source.seen), 2, source.seen)

    def test_a_process_is_read_again_only_when_its_pid_changed_hands(self):
        class Proc:
            def __init__(self, alive):
                self.alive = alive

            def is_running(self):
                return self.alive

        self.assertTrue(b.same_process({"proc": Proc(True)}))
        self.assertFalse(b.same_process({"proc": Proc(False)}))
        self.assertTrue(b.same_process({}))
        if b.psutil is not None:
            table = b.process_table()
            mine = table[os.getpid()]
            self.assertTrue(b.same_process(mine))
            self.assertIs(b.process_table(table)[os.getpid()], mine)

    def test_looking_for_procmon_reads_no_parent_ids(self):
        asked = []

        class Proc:
            def __init__(self, pid):
                self.pid = pid

            def oneshot(self):
                return contextlib.nullcontext()

            def name(self):
                return "Procmon64.exe" if self.pid == 7 else "other.exe"

            def create_time(self):
                return 100.0

            def ppid(self):
                asked.append(self.pid)
                return 1

        class Fake:
            Process = Proc

            @staticmethod
            def pids():
                return [5, 7]

        source = b.ProcMonSource(FakeSession())
        source.launched = 99.0
        saved = b.psutil
        try:
            b.psutil = Fake
            self.assertEqual(source._procmon_pids(), {7})
            self.assertEqual(asked, [])
            self.assertEqual(b.process_table()[5]["ppid"], 1)
        finally:
            b.psutil = saved

    def test_a_kernel_exit_names_the_program_in_full(self):
        now = time.time()
        source = self.source()
        source.session.devices = b.DeviceMap()
        source.etw_started(3999011, 0, "eventcreate.exe", now - 1.0, "")
        source.etw_exited(3999011, 0, "eventcreate.ex", now)
        b.PROCESS_NAMES.put(3999012, "notepad.exe")
        source.etw_exited(3999012, 0, "RuntimeBroker.", now)
        self.assertEqual(len(source.seen), 3, source.seen)
        self.assertTrue(source.seen[1].startswith("Exited eventcreate.exe (PID 3999011)"), source.seen)
        self.assertTrue(source.seen[2].startswith("Exited RuntimeBroker. (PID 3999012)"), source.seen)


class Window(unittest.TestCase):
    def setUp(self):
        try:
            self.root = b.tk.Tk()
        except b.tk.TclError as exc:
            self.skipTest("no display: %s" % exc)
        self.root.withdraw()
        self.home = tempfile.mkdtemp()
        self.saved = (b.SETTINGS_PATH, b.DATA_DIR, b.EXCLUSIONS_PATH, b.load_exclusions.__defaults__,
                      b.save_exclusions.__defaults__, b.PROGRAM_DIR)
        b.DATA_DIR = self.home
        b.PROGRAM_DIR = self.home
        b.SETTINGS_PATH = os.path.join(self.home, "settings.json")
        b.EXCLUSIONS_PATH = os.path.join(self.home, "Exclusions.ini")
        b.load_exclusions.__defaults__ = (b.EXCLUSIONS_PATH,)
        b.save_exclusions.__defaults__ = (b.EXCLUSIONS_PATH,)

    def tearDown(self):
        (b.SETTINGS_PATH, b.DATA_DIR, b.EXCLUSIONS_PATH, b.load_exclusions.__defaults__,
         b.save_exclusions.__defaults__, b.PROGRAM_DIR) = self.saved
        shutil.rmtree(self.home, ignore_errors=True)

    def test_a_window_left_on_a_screen_left_of_the_main_one_still_starts(self):
        saved = b.screen_box
        try:
            b.screen_box = lambda _root: (-1920, 0, 3840, 1080)
            self.assertTrue(b.geometry_fits(self.root, "1200x800+-1500+40"))
            self.assertFalse(b.geometry_fits(self.root, "1200x800+-2500+40"))
        finally:
            b.screen_box = saved
        self.assertFalse(b.geometry_fits(self.root, "1200x800--1500+40"))
        with open(b.SETTINGS_PATH, "w", encoding="utf-8") as fh:
            json.dump({"geometry": "1440x880+-1920+100", "sort": ["time"], "show": 1e999}, fh)
        app = b.App(self.root, b.parse_options([]), b.setup_style(self.root))
        self.assertEqual(app.sort_column, "")
        self.assertEqual(app.show_index, 0)

    def test_the_status_line_never_says_the_log_holds_what_it_stopped_before(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        app.rules.set_lines([])
        app.store = b.Store(limit=5)
        now = time.time()
        for index in range(9):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()

        class Done:
            writer = b.LogWriter(os.path.join(self.home, "t.log"), ["h"], 1024 * 1024)
            finished = b.threading.Event()
            stop_event = b.threading.Event()

        Done.writer.capped = True
        app.session = Done()
        self.assertIn("4 more did not fit in the timeline, and the log stopped at its 1 MB limit", app._status_text())
        Done.writer.capped = False
        self.assertIn("4 more are only in the log", app._status_text())

    def test_the_panel_says_hidden_at_once_and_in_full(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        app.hub.set_status(b.SRC_PROBE, "done", "settings read once at start")
        app.hub.set_status(b.SRC_ETW, "running", "Kernel-Registry, Kernel-File, Shell-Core, Immersive-Shell, Themes")
        app._refresh()
        probes = app.rows[b.SRC_PROBE]
        probes.toggle()
        self.assertTrue(probes.info.cget("text").endswith(", hidden"), probes.info.cget("text"))
        probes.toggle()
        self.assertEqual(probes.info.cget("text"), "settings read once at start")
        etw = app.rows[b.SRC_ETW]
        etw.toggle()
        self.assertTrue(etw.info.cget("text").endswith(", hidden"), etw.info.cget("text"))
        self.assertLessEqual(len(etw.info.cget("text")), 36)

    def test_the_list_holds_only_what_the_timeline_kept(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        app.rules.set_lines([])
        app.store = b.Store(limit=10)
        now = time.time()
        for index in range(30):
            app.hub.emit(b.SRC_ETW, b.KIND_ETW, "[Kernel-Registry] read %d" % index, b.INFO, ts=now + index)
        app._drain()
        self.assertEqual(len(app.tree.get_children()), len(app.store.events()))
        for iid in app.tree.get_children():
            self.assertIn(int(iid), app.store.by_seq)

    def test_a_rebuild_keeps_the_place_the_list_was_scrolled_to(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.root.deiconify()
        self.root.geometry("1200x700")
        now = time.time()
        for index in range(600):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        if app.rebuild_job is not None:
            app.root.after_cancel(app.rebuild_job)
            app.rebuild_job = None
        app._rebuild()
        self.root.update()
        app.tree.selection_remove(*app.tree.selection())
        app.tree.yview_moveto(0.4)
        self.root.update()
        before = app.tree.yview()[0]
        self.assertGreater(before, 0.2)
        self.assertLess(before, 0.8)
        app._rebuild()
        self.root.update()
        self.assertEqual(len(app.tree.get_children()), 600)
        self.assertAlmostEqual(app.tree.yview()[0], before, places=2)

    def test_a_rebuild_still_follows_the_newest_when_at_the_bottom(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.root.deiconify()
        self.root.geometry("1200x700")
        now = time.time()
        for index in range(600):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        if app.rebuild_job is not None:
            app.root.after_cancel(app.rebuild_job)
            app.rebuild_job = None
        app._rebuild()
        app.tree.selection_remove(*app.tree.selection())
        app.tree.yview_moveto(1.0)
        self.root.update()
        app._rebuild()
        self.root.update()
        self.assertGreaterEqual(app.tree.yview()[1], 0.999)

    def test_the_clear_button_empties_the_list_only(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        for index in range(40):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        if app.rebuild_job is not None:
            app.root.after_cancel(app.rebuild_job)
            app.rebuild_job = None
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 40)
        app.clear_timeline()
        self.assertEqual(len(app.tree.get_children()), 0)
        self.assertEqual(len(app.store.events()), 0)
        self.assertEqual(app.match_count, 0)
        self.assertEqual(app.view_count, 0)
        self.assertIsNone(app.rebuild_job)
        app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\After", b.CHANGE, ts=now + 99)
        app._drain()
        self.assertEqual(len(app.tree.get_children()), 1)

    def test_rows_not_yet_listed_when_clear_is_pressed_stay_out_of_the_list(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Before", b.CHANGE, ts=now)
        app.clear_timeline()
        after = app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\After", b.CHANGE, ts=now + 1)
        app._drain()
        self.assertEqual(app.tree.get_children(), (str(after.seq),))
        self.assertEqual(len(app.store.events()), 1)

    def test_the_clear_button_sits_between_filter_and_options(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        bar = app.btn_options.master
        packed = [child for child in bar.pack_slaves() if child.pack_info().get("side") == "right"]
        visual = list(reversed([str(child) for child in packed]))
        self.assertEqual(app.btn_clear.cget("text"), "Clear")
        self.assertEqual(visual.index(str(app.btn_clear)), visual.index(str(app.btn_filter)) + 1)
        self.assertEqual(visual.index(str(app.btn_options)), visual.index(str(app.btn_clear)) + 1)

    def test_the_export_button_sits_before_filter_and_saves_either_file(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        bar = app.btn_options.master
        packed = [child for child in bar.pack_slaves() if child.pack_info().get("side") == "right"]
        visual = list(reversed([str(child) for child in packed]))
        self.assertEqual(app.btn_export.cget("text"), "Export")
        self.assertEqual(visual.index(str(app.btn_filter)), visual.index(str(app.btn_export)) + 1)
        menu = app.export_popup
        self.assertEqual(menu.index("end"), 1)
        self.assertEqual([(menu.entrycget(index, "label"), menu.entrycget(index, "accelerator")) for index in (0, 1)],
                         [("Save as CSV", "Ctrl+S"), ("Save as JSON", "Ctrl+J")])
        asked = []
        app.export = asked.append
        menu.invoke(0)
        menu.invoke(1)
        self.assertEqual(asked, ["csv", "json"])

    def test_escape_closes_the_filter_and_options_windows(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.root.deiconify()
        self.root.update()
        for open_it in (app.edit_filter, app.edit_options):
            open_it()
            self.root.update()
            windows = [w for w in self.root.winfo_children() if isinstance(w, b.tk.Toplevel)]
            self.assertEqual(len(windows), 1, open_it.__name__)
            window = windows[0]
            self.assertTrue(window.bind("<Escape>"), open_it.__name__)
            app._close_dialog(window)
            self.root.update()
            self.assertEqual([w for w in self.root.winfo_children() if isinstance(w, b.tk.Toplevel)], [],
                             open_it.__name__)
            app._close_dialog(window)

    def test_the_panel_on_the_left_lists_every_source_in_order(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.assertEqual(list(app.rows), list(b.SOURCE_NAMES))
        left = app.rows[b.SOURCE_NAMES[0]].master
        placed = [str(app.rows[name]) for name in b.SOURCE_NAMES]
        order = [str(child) for child in left.pack_slaves()]
        self.assertEqual([one for one in order if one in placed], placed)
        for name in b.SOURCE_NAMES:
            self.assertTrue(app.rows[name].on, name)
            self.assertTrue(app.rows[name].bind("<Button-1>"), name)
            self.assertTrue(app.rows[name].title.bind("<Button-1>"), name)

    def test_clicking_a_source_row_hides_its_events(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Control Panel\\Desktop [WallPaper]", b.CHANGE, ts=now)
        app.hub.emit(b.SRC_PROC, b.KIND_PROC, "Started Photos.exe (PID 7)", ts=now + 1)
        app.hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "Trace started", ts=now + 2)
        app._drain()
        if app.rebuild_job is not None:
            app.root.after_cancel(app.rebuild_job)
            app.rebuild_job = None
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 3)
        app.rows[b.SRC_PROC].toggle()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 2)
        self.assertFalse(app.rows[b.SRC_PROC].on)
        self.assertEqual(app.rows[b.SRC_PROC].title.cget("fg"), b.Theme.MUTE)
        app.rows[b.SRC_PROC].toggle()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 3)
        self.assertEqual(app.rows[b.SRC_PROC].title.cget("fg"), b.Theme.FG)

    def test_the_system_channel_cannot_be_hidden_by_a_row(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.assertNotIn(b.SRC_SYSTEM, app.rows)
        now = time.time()
        app.hub.emit(b.SRC_SYSTEM, b.KIND_SYS, "Trace stopped after 8 seconds", ts=now)
        app._drain()
        if app.rebuild_job is not None:
            app.root.after_cancel(app.rebuild_job)
            app.rebuild_job = None
        for row in app.rows.values():
            row.on = False
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 1)

    def test_the_rows_that_are_hidden_are_kept_for_the_next_start(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        app.rows[b.SRC_ETW].toggle()
        app.rows[b.SRC_PM].toggle()
        app._save_settings()
        saved = b.load_settings()
        self.assertFalse(saved["sources"][b.SRC_ETW])
        self.assertFalse(saved["sources"][b.SRC_PM])
        self.assertTrue(saved["sources"][b.SRC_REG])
        self.assertNotIn("kinds", saved)
        self.assertEqual(sorted(saved["sources"]), sorted(b.SOURCE_NAMES))

    def test_filters_search_and_selection(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Control Panel\\Desktop [WallPaper] changed", b.CHANGE, ts=now)
        app.hub.emit(b.SRC_PROC, b.KIND_PROC, "Started Photos.exe (PID 7)", pid=7, proc="Photos.exe", ts=now + 1)
        app.hub.emit(b.SRC_LOG, b.KIND_LOG, "Application: Error 1000", b.ERROR, ts=now + 2)
        app.hub.emit(b.SRC_SYSTEM, b.KIND_MARK, "Marker 1", b.MARK, ts=now + 3)
        app._drain()
        self.assertEqual(len(app.tree.get_children()), 4)
        app.hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: late", b.CHANGE, ts=now - 5)
        app._drain()
        self.assertIsNone(app.rebuild_job)
        self.assertEqual(app.tree.get_children()[0], str(app.store.events()[0].seq))
        self.assertEqual(len(app.tree.get_children()), 5)
        app.show_box.current(2)
        app._filters_changed()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 2)
        app.show_box.current(0)
        app.search_var.set("photos")
        app._filters_changed()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 2)
        app.rows[b.SRC_PROC].toggle()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 1)
        app.rows[b.SRC_PROC].toggle()
        app.search_var.set("")
        app._filters_changed()
        app._rebuild()
        first = app.tree.get_children()[2]
        app.tree.selection_set(first)
        app._selected()
        self.assertIn("Process:  Photos.exe (PID 7)", app.detail.get("1.0", "end"))
        app.copy_selection()
        try:
            copied = self.root.clipboard_get()
        except b.tk.TclError:
            copied = None
        if copied is not None:
            self.assertIn("Started Photos.exe", copied)
        app.on_close()
        with open(b.SETTINGS_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual(saved["show"], 0)
        self.assertTrue(saved["sources"][b.SRC_PROC])

    def test_a_sorted_list_takes_new_rows_without_a_full_redraw(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        app._sort_by("process")
        now = time.time()
        names = ["delta.exe", "alpha.exe", "echo.exe", "charlie.exe", "bravo.exe"]
        for index in range(200):
            app.hub.emit(b.SRC_PROC, b.KIND_PROC, "Started %d" % index, proc=names[index % 5], ts=now + index)
        app._drain()
        calls = {"match": 0, "rebuild": 0}
        match, rebuild = app._match, app._rebuild

        def counted_match(ev):
            calls["match"] += 1
            return match(ev)

        def counted_rebuild(*args):
            calls["rebuild"] += 1
            return rebuild(*args)

        app._match = counted_match
        app._rebuild = counted_rebuild
        for index in range(30):
            app.hub.emit(b.SRC_PROC, b.KIND_PROC, "Later %d" % index, proc=names[index % 5], ts=now + 500 + index)
        app._drain()
        self.assertEqual(calls, {"match": 30, "rebuild": 0})
        self.assertIsNone(app.rebuild_job)
        self.assertIsNone(app.reload_job)
        listed = [app.store.by_seq[int(iid)] for iid in app.tree.get_children()]
        self.assertEqual(len(listed), 230)
        self.assertEqual(listed, sorted(listed, key=b.SORT_KEYS["process"]))

    def test_the_list_always_shows_what_a_full_redraw_would(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        saved = (b.VIEW_LIMIT, b.MERGE_LIMIT)
        rng = random.Random(30)
        names = ["delta.exe", "alpha.exe", "echo.exe", "", "bravo.exe"]
        orders = [("", False), ("time", True), ("process", False), ("process", True), ("event", False),
                  ("pid", True), ("source", False), ("kind", True)]
        try:
            b.VIEW_LIMIT = 40
            b.MERGE_LIMIT = 6
            now = time.time()
            for step in range(160):
                if step % 20 == 0:
                    app.sort_column, app.sort_down = orders[step // 20]
                    app._paint_headings()
                    app._reload(False)
                if step % 25 == 12:
                    app.rows[b.SRC_REG].toggle()
                for _index in range(rng.randint(1, 25)):
                    ts = now + step + rng.random() if rng.random() < 0.6 else now + rng.uniform(0, step + 1)
                    app.hub.emit(rng.choice((b.SRC_PROC, b.SRC_REG, b.SRC_FILES)), rng.choice((b.KIND_PROC, b.KIND_FILE)),
                                 "row %d" % rng.randint(0, 999), rng.choice((b.INFO, b.CHANGE, b.ERROR)),
                                 pid=rng.randint(1, 50), proc=rng.choice(names), ts=ts)
                app._drain()
                if app.rebuild_job is not None:
                    self.root.after_cancel(app.rebuild_job)
                    app._rebuild()
                if app.reload_job is not None:
                    self.root.after_cancel(app.reload_job)
                    app._reload()
                key, down = app._order()
                matches = [ev for ev in app.store.events() if app._match(ev)]
                newest = matches[-b.VIEW_LIMIT:]
                wanted = [str(ev.seq) for ev in sorted(newest, key=key, reverse=down)]
                self.assertEqual(list(app.tree.get_children()), wanted, step)
                self.assertEqual(app.shown, sorted(key(ev) for ev in newest), step)
                self.assertEqual((app.match_count, app.view_count), (len(matches), len(newest)), step)
        finally:
            b.VIEW_LIMIT, b.MERGE_LIMIT = saved

    def test_many_rows_arriving_out_of_order_are_drawn_in_one_go(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        for index in range(100):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Live%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        for index in range(b.MERGE_LIMIT + 50):
            app.hub.emit(b.SRC_PM, b.KIND_REG, "RegSetValue HKCU\\Software\\Late%d" % index, b.CHANGE,
                         ts=now + index * 100.0 / (b.MERGE_LIMIT + 50))
        app._drain()
        self.assertIsNotNone(app.reload_job)
        self.assertEqual(len(app.tree.get_children()), 100)
        self.root.after_cancel(app.reload_job)
        app._reload()
        self.assertIsNone(app.reload_job)
        listed = [app.store.by_seq[int(iid)] for iid in app.tree.get_children()]
        self.assertEqual(len(listed), 150 + b.MERGE_LIMIT)
        self.assertEqual(listed, sorted(listed, key=b.Event.key))

    def test_a_list_scrolled_up_keeps_its_place_when_older_rows_arrive(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.root.deiconify()
        self.root.geometry("1200x700")
        now = time.time()
        for index in range(400):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        self.root.update()
        app.tree.yview(200)
        self.root.update()
        top = app.tree.get_children()[200]
        before = app.tree.bbox(top)
        self.assertTrue(before)
        for index in range(30):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Early%d" % index, b.CHANGE, ts=now - 100 + index)
        app._drain()
        self.root.update()
        self.assertEqual(app.tree.get_children()[230], top)
        self.assertEqual(app.tree.bbox(top), before)

    def test_the_list_follows_new_rows_when_it_is_at_the_bottom(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        self.root.deiconify()
        self.root.geometry("1200x700")
        now = time.time()
        for index in range(400):
            app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\Thing%d" % index, b.CHANGE, ts=now + index)
        app._drain()
        self.root.update()
        app.tree.yview_moveto(1.0)
        self.root.update()
        last = None
        for index in range(50):
            last = app.hub.emit(b.SRC_REG, b.KIND_REG, "HKCU\\Software\\New%d" % index, b.CHANGE, ts=now + 500 + index)
        app._drain()
        self.root.update()
        self.assertEqual(app.tree.get_children()[-1], str(last.seq))
        self.assertGreaterEqual(app.tree.yview()[1], 0.999)

    def test_redrawing_the_list_adds_nothing_to_the_left_out_count(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        for index in range(20):
            app.hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick%d.txt" % index, b.CHANGE, ts=now + index)
        app._drain()
        self.assertEqual(len(app.tree.get_children()), 20)
        app.rules.set_lines(["Files | | tick"])
        app.rules.enabled = True
        app.rules.reset_count()
        for _index in range(3):
            app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 0)
        self.assertEqual(app.rules.blocked, 0)

    def test_a_redraw_reads_the_filter_again_only_once_it_has_changed(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        for index in range(20):
            app.hub.emit(b.SRC_FILES, b.KIND_FILE, "File changed: tick%d.txt" % index, b.CHANGE, ts=now + index)
        app._drain()
        checked = []
        blocks = app.rules.blocks
        app.rules.blocks = lambda *args: checked.append(args) or blocks(*args)
        app._rebuild()
        self.assertEqual((checked, len(app.tree.get_children())), ([], 20))
        app.rules.set_lines(["Files | | tick1"])
        app._rebuild()
        self.assertEqual((len(checked), len(app.tree.get_children())), (20, 9))
        app._rebuild()
        self.assertEqual((len(checked), len(app.tree.get_children())), (20, 9))

    def test_a_repeated_row_shows_its_count_in_the_list_and_the_detail(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        now = time.time()
        text = "File changed: C:\\x\\tick.txt"
        first = app.hub.emit(b.SRC_FILES, b.KIND_FILE, text, b.CHANGE, ts=now)
        app.hub.emit(b.SRC_FILES, b.KIND_FILE, text, b.CHANGE, ts=now + 1)
        app._drain()
        iid = str(first.seq)
        self.assertEqual(app.tree.get_children(), (iid,))
        self.assertEqual(app.tree.item(iid, "values")[-1], text + " (2 times)")
        app.tree.selection_set(iid)
        app._selected()
        app.hub.emit(b.SRC_FILES, b.KIND_FILE, text, b.CHANGE, ts=now + 2)
        app._drain()
        self.assertEqual(app.tree.item(iid, "values")[-1], text + " (3 times)")
        self.assertIn(text + " (3 times)", app.detail.get("1.0", "end"))
        app.clear_timeline()
        again = app.hub.emit(b.SRC_FILES, b.KIND_FILE, text, b.CHANGE, ts=now + 3)
        app._drain()
        self.assertEqual(app.tree.get_children(), (str(again.seq),))
        self.assertEqual(app.tree.item(str(again.seq), "values")[-1], text)
        self.assertEqual(first.count, 3)

    def test_a_rule_from_the_menu_leaves_the_filter_switch_alone(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        saved = b.save_exclusions
        written = []
        try:
            b.save_exclusions = lambda rules, path=None: written.append(list(rules.lines)) or ""
            app.rules.enabled = False
            ev = app.hub.emit(b.SRC_PROC, b.KIND_PROC, "Started noisy.exe (PID 7)", pid=7, proc="noisy.exe")
            app._drain()
            app.menu_row = str(ev.seq)
            app.exclude_process()
            self.assertFalse(app.rules.enabled)
            self.assertEqual(app.rules.lines[-1], "Processes | | process=noisy.exe")
            self.assertEqual(written, [app.rules.lines])
            self.assertIn("Use these rules is off", app.flash_text)
            self.assertIsNone(app.rebuild_job)
            self.assertEqual(len(app.tree.get_children()), 1)
            app.rules.enabled = True
            app.exclude_selected()
            self.assertTrue(app.rules.enabled)
            self.assertTrue(app.flash_text.startswith("Left out from now on: "), app.flash_text)
        finally:
            b.save_exclusions = saved


class ReleaseNotes(unittest.TestCase):
    def test_only_the_notes_that_differ_are_rewritten(self):
        changelog = ("# Changelog\n\n## Unreleased\n\n- Coming.\n\n## 1.1.0\n\n- New one.\n- Two.\n\n"
                     "## 1.0.0\n\n- First.\n")
        releases = [{"tag": "v1.1.0", "body": "- Old one.\n- Two.\n", "draft": False},
                    {"tag": "v1.0.0", "body": "- First.\r\n", "draft": False},
                    {"tag": "v0.9.0", "body": "- Gone.\n", "draft": False},
                    {"tag": "v1.2.0", "body": "- Draft.\n", "draft": True},
                    {"tag": "nightly", "body": "x", "draft": False}]
        changes, missing = notes_sync.plan(changelog, releases)
        self.assertEqual(changes, [("v1.1.0", "- New one.\n- Two.\n")])
        self.assertEqual(missing, ["v0.9.0"])

    def test_the_notes_read_the_changelog_the_way_the_gate_does(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(notes_sync.sections(text), {name: entries for name, entries in gate.sections(text)})
        self.assertEqual(notes_sync.notes(["One.", "Two."]), "- One.\n- Two.\n")

    def test_the_workflow_brings_the_notes_in_line_after_the_source_rules(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), "r", encoding="utf-8") as fh:
            text = fh.read()
        sync = text.index("python tools/sync_release_notes.py")
        self.assertLess(text.index("name: Check the source rules"), sync)
        self.assertLess(sync, text.index("name: Install the dependencies"))
        step = text[text.rindex("- name:", 0, sync):sync]
        self.assertIn("if: github.ref == 'refs/heads/main'", step)
        self.assertIn("GH_TOKEN: ${{ github.token }}", step)


class SourceCheck(unittest.TestCase):
    def test_an_unreadable_old_file_is_still_checked_around_its_broken_line(self):
        text = "\n".join(['def f():', '    "a docstring"', '    x = "%s"' % ("y" * 300), "    z = ('a', {b}')",
                          "    return x  # note", ""])
        report = source_check.Report()
        source_check.check_python("OldDevelopments/x.py", text, report, strict=False)
        self.assertEqual(sorted(error.split(": ", 1)[0] for error in report.errors),
                         ["OldDevelopments/x.py:2", "OldDevelopments/x.py:3", "OldDevelopments/x.py:5"])
        self.assertEqual([note.split(": ", 1)[0] for note in report.notes], ["OldDevelopments/x.py:4"])
        strict = source_check.Report()
        source_check.check_python("bastard.pyw", text, strict)
        self.assertEqual(len(strict.errors), 1)

    def test_a_try_left_without_its_except_is_skipped_on_its_own(self):
        text = "\n".join(["for item in range(3):", "    try:", "        a = item  # note", "    except Exception:",
                          "        pass", "    try:", "        b = item", "c = 2", ""])
        report = source_check.Report()
        source_check.check_python("OldDevelopments/y.py", text, report, strict=False)
        self.assertEqual([note.split(": ", 1)[0] for note in report.notes], ["OldDevelopments/y.py:6"])
        self.assertEqual([error.split(": ", 1)[0] for error in report.errors], ["OldDevelopments/y.py:3"])


class ReleaseGate(unittest.TestCase):
    def git(self, folder, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_COMMITTER_NAME="Test", GIT_AUTHOR_EMAIL="",
                   GIT_COMMITTER_EMAIL="")
        result = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"] + list(args),
                                cwd=folder, env=env, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def commit(self, folder, version, sections, subject):
        with open(os.path.join(folder, "bastard.pyw"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write('VERSION = "%s"\n' % version)
        with open(os.path.join(folder, "CHANGELOG.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# Changelog\n" + "".join("\n## %s\n\n- %s\n" % pair for pair in sections))
        self.git(folder, "add", "-A")
        self.git(folder, "commit", "-q", "-m", subject, "-m", "- " + sections[0][1])
        return self.git(folder, "rev-parse", "HEAD")

    def gate(self, folder, before, after):
        here = os.getcwd()
        out = io.StringIO()
        saved = os.environ.pop("GITHUB_OUTPUT", None)
        try:
            os.chdir(folder)
            with contextlib.redirect_stdout(out):
                code = gate.main(["--before", before, "--after", after, "--notes", os.path.join(folder, "notes.md")])
        finally:
            os.chdir(here)
            if saved is not None:
                os.environ["GITHUB_OUTPUT"] = saved
        return code, out.getvalue()

    def test_a_version_must_be_above_the_newest_release(self):
        folder = tempfile.mkdtemp(prefix="bastard_gate_")
        try:
            self.git(folder, "init", "-q", ".")
            first = self.commit(folder, "1.8.0", [("1.8.0", "Bastard 1.8.0 is out.")], "[1.8.0] Bastard: ship it")
            self.git(folder, "tag", "v1.8.0")
            lower = self.commit(folder, "1.7.0", [("1.7.0", "Bastard 1.7.0 again."), ("1.8.0", "Bastard 1.8.0 is out.")],
                                "[1.7.0] Bastard: go back")
            code, out = self.gate(folder, first, lower)
            self.assertEqual(code, 1, out)
            self.assertIn("version 1.7.0 is not above the newest release, 1.8.0", out)
            higher = self.commit(folder, "1.8.1", [("1.8.1", "Bastard 1.8.1 fixes it."), ("1.8.0", "Bastard 1.8.0 is out.")],
                                 "[1.8.1] Bastard: fix it")
            code, out = self.gate(folder, lower, higher)
            self.assertEqual(code, 0, out)
            self.assertIn("Version 1.8.1 will be published", out)
            self.assertIn("Release title: Bastard 1.8.1", out)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_only_one_version_carries_a_release_name(self):
        self.assertEqual(gate.release_title("1.11.0"), "Bastard 1.11.0 (Grok Tribute Release)")
        self.assertEqual(gate.release_title("1.11.1"), "Bastard 1.11.1")
        self.assertEqual(gate.release_title("1.10.2"), "Bastard 1.10.2")
        self.assertEqual(list(gate.RELEASE_NAMES), ["1.11.0"])

    def test_the_gate_hands_the_workflow_a_release_title(self):
        folder = tempfile.mkdtemp(prefix="bastard_gate_")
        outputs = os.path.join(folder, "outputs.txt")
        saved = os.environ.get("GITHUB_OUTPUT")
        here = os.getcwd()
        try:
            self.git(folder, "init", "-q", ".")
            first = self.commit(folder, "1.10.2", [("1.10.2", "Bastard 1.10.2 is out.")], "[1.10.2] Bastard: ship it")
            self.git(folder, "tag", "v1.10.2")
            named = self.commit(folder, "1.11.0", [("1.11.0", "Bastard 1.11.0 is out."), ("1.10.2", "Bastard 1.10.2 is out.")],
                                "[1.11.0] Bastard: ship the next one")
            os.environ["GITHUB_OUTPUT"] = outputs
            os.chdir(folder)
            with contextlib.redirect_stdout(io.StringIO()):
                code = gate.main(["--before", first, "--after", named, "--notes", os.path.join(folder, "notes.md")])
            self.assertEqual(code, 0)
            with open(outputs, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            self.assertEqual(lines, ["publish=true", "version=1.11.0", "title=Bastard 1.11.0 (Grok Tribute Release)"])
            with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as fh:
                workflow = fh.read()
            self.assertIn('--title "${{ steps.gate.outputs.title }}"', workflow)
        finally:
            os.chdir(here)
            if saved is None:
                os.environ.pop("GITHUB_OUTPUT", None)
            else:
                os.environ["GITHUB_OUTPUT"] = saved
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
