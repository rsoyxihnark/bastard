import importlib.machinery
import importlib.util
import io
import json
import os
import queue
import shutil
import tempfile
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


def event(ts, source="Files", kind="File", level="change", text="x", proc="", pid=None, seq=None):
    event.counter += 1
    return b.Event(ts, seq or event.counter, source, kind, level, pid, proc, text, "")


event.counter = 0


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
        old = ({"", "Sub", "Gone", "Gone\\Deep"}, {("", "A"): (4, 1), ("", "B"): (1, "x"), ("Gone", "V"): (4, 1),
                                                  ("Gone\\Deep", "W"): (4, 2)})
        new = ({"", "Sub", "New", "New\\Inner"}, {("", "A"): (4, 2), ("", "C"): (1, "y"), ("New", "N"): (4, 5)})
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


class NewSources(unittest.TestCase):
    def test_reg_helpers_guard(self):
        self.assertIsNone(b.reg_read_value(None, "Software\\X", "Y"))
        self.assertFalse(b.reg_key_exists(None, "Software\\X"))

    def test_source_registry(self):
        names = [cls.name for cls in b.SOURCE_TYPES]
        for wanted in (b.SRC_ETW, b.SRC_WMI, b.SRC_PROBE, b.SRC_TRACE):
            self.assertIn(wanted, names)
        self.assertEqual(b.ETW_GUID_NAMES["{70EB4F03-C1DE-4F73-A051-33D13D541355}"], "Kernel-Registry")

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
            (b.SRC_SYSTEM, b.MARK, "Marker 1: 4 events in the 6 seconds after it"),
            (b.SRC_FILES, b.CHANGE, "File created: x.txt"),
            (b.SRC_FILES, b.CHANGE, "renamed x.txt to y.txt"),
            (b.SRC_FILES, b.CHANGE, "deleted y.txt"),
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

    def test_the_defaults_are_the_six_the_owner_asked_for(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertEqual(len(rules.rules), 6)
        self.assertTrue(rules.blocks(b.SRC_PM, b.INFO,
                                     "read RegQueryValue HKCU\\SOFTWARE\\Microsoft\\Windows\\DWM"
                                     "\\ColorPrevalence"))
        self.assertTrue(rules.blocks(b.SRC_PROBE, b.INFO, "D: DisallowRun policy"))
        self.assertTrue(rules.blocks(b.SRC_REG, b.CHANGE, "HKLM\\...\\Certificates\\Root added"))
        self.assertFalse(rules.blocks(b.SRC_PM, b.INFO, "read QueryOpen C:\\x.dll"))

    def test_the_defaults_leave_the_kernel_file_reads_out(self):
        rules = b.Exclusions(b.DEFAULT_EXCLUSIONS)
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "[Kernel-File] Irp=0xFF | Status=0x0"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "[Microsoft-Windows-Kernel-File] Irp=0xFF"))
        self.assertTrue(rules.blocks(b.SRC_ETW, b.INFO, "x", "", "Provider: Kernel-File\nFileName=C:\\a.jpg"))
        self.assertFalse(rules.blocks(b.SRC_ETW, b.INFO, "[Kernel-Registry] RegSetValue HKCU\\Software"))
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
        self.assertEqual(b.process_exclusion_from(ev), "ProcMon | | explorer.exe")
        rules = b.Exclusions([b.process_exclusion_from(ev)])
        self.assertTrue(rules.blocks(ev.source, ev.level, ev.text, ev.proc))
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
                     "ProcMon: read 1000 events", "Marker 1: 4 events in the 6 seconds after it"):
            self.assertFalse(rules.blocks(b.SRC_SYSTEM, b.INFO, text), text)
        self.assertEqual(rules.blocked, 0)

    def test_marker_summary(self):
        text, level, _ = b.marker_summary(2, 100.0, [event(99.0), event(107.0)])
        self.assertEqual(level, b.WARN)
        self.assertEqual(text, "Marker 2: nothing happened in the 6 seconds after it")
        events = [event(101.0, proc="Photos.exe"), event(102.0, "Registry", "Registry", proc="Photos.exe"),
                  event(103.0, "System", "System"), event(105.9, proc="x.exe")]
        text, level, detail = b.marker_summary(1, 100.0, events)
        self.assertEqual(level, b.MARK)
        self.assertEqual(text, "Marker 1: 3 events in the 6 seconds after it (Files 2, Registry 1), from Photos.exe, x.exe")
        self.assertEqual(len(detail.splitlines()), 3)

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
            self.assertEqual(data["bastard"], b.VERSION)
            with open(os.path.join(folder, "e.csv"), encoding="utf-8-sig") as fh:
                self.assertTrue(fh.readline().startswith("Time,Source,Kind,Level,Process,PID,Event,Detail"))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_options(self):
        options = b.parse_options(["--selftest", "r.json", "--watch-key", "HKCU\\X", "--seconds", "12", "--bogus"])
        self.assertTrue(options["selftest"].endswith("r.json"))
        self.assertEqual(options["watch_keys"], ["HKCU\\X"])
        self.assertEqual(options["seconds"], 12.0)
        self.assertEqual(b.duration_clock(3725), "01:02:05")


class Window(unittest.TestCase):
    def setUp(self):
        try:
            self.root = b.tk.Tk()
        except b.tk.TclError as exc:
            self.skipTest("no display: %s" % exc)
        self.root.withdraw()
        self.home = tempfile.mkdtemp()
        self.saved = (b.SETTINGS_PATH, b.DATA_DIR)
        b.DATA_DIR = self.home
        b.SETTINGS_PATH = os.path.join(self.home, "settings.json")

    def tearDown(self):
        b.SETTINGS_PATH, b.DATA_DIR = self.saved
        shutil.rmtree(self.home, ignore_errors=True)

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

    def test_the_clear_button_sits_between_filter_and_options(self):
        scale = b.setup_style(self.root)
        app = b.App(self.root, b.parse_options([]), scale)
        bar = app.btn_options.master
        packed = [child for child in bar.pack_slaves() if child.pack_info().get("side") == "right"]
        visual = list(reversed([str(child) for child in packed]))
        self.assertEqual(app.btn_clear.cget("text"), "Clear")
        self.assertEqual(visual.index(str(app.btn_clear)), visual.index(str(app.btn_filter)) + 1)
        self.assertEqual(visual.index(str(app.btn_options)), visual.index(str(app.btn_clear)) + 1)

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
        app.root.after_cancel(app.rebuild_job)
        app._rebuild()
        self.assertEqual(app.tree.get_children()[0], str(app.store.events()[0].seq))
        app.show_box.current(2)
        app._filters_changed()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 2)
        app.show_box.current(0)
        app.search_var.set("photos")
        app._filters_changed()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 2)
        app.source_chips[b.SRC_PROC]._toggle()
        app._rebuild()
        self.assertEqual(len(app.tree.get_children()), 1)
        app.source_chips[b.SRC_PROC]._toggle()
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


if __name__ == "__main__":
    unittest.main()
