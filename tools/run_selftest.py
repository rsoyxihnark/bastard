import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

IS_WIN = os.name == "nt"
KEY = "Software\\TraceSelfTest"
WORK_PREFIX = "trace_selftest_"
SECONDS = 32
MARKER_AT = 10


def has(events, *parts, source=None):
    for ev in events:
        if source and ev["source"] != source:
            continue
        text = ev["event"].lower()
        if all(part.lower() in text for part in parts):
            return True
    return False


def wait_for(path, proc, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.isfile(path):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.2)
    return False


def registry_actions():
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY) as key:
        winreg.SetValueEx(key, "A", 0, winreg.REG_DWORD, 2)
        time.sleep(0.4)
        winreg.SetValueEx(key, "B", 0, winreg.REG_SZ, "hello")
        time.sleep(0.4)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY + "\\Sub") as key:
        winreg.SetValueEx(key, "C", 0, winreg.REG_DWORD, 3)
    time.sleep(0.6)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_ALL_ACCESS) as key:
        winreg.DeleteValue(key, "B")
    time.sleep(0.4)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, KEY + "\\Sub")


def prepare_registry():
    import winreg
    cleanup_registry()
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY) as key:
        winreg.SetValueEx(key, "A", 0, winreg.REG_DWORD, 1)


def cleanup_registry():
    import winreg
    for sub in (KEY + "\\Sub", KEY):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            pass


def etw_session_state(path):
    try:
        result = subprocess.run(["logman", "query", "Bastard ETW Trace", "-ets"], capture_output=True, text=True,
                                timeout=10)
        text = result.stdout + result.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        text = str(exc)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def run_actions(folder, log):
    first = os.path.join(folder, "x.txt")
    second = os.path.join(folder, "y.txt")
    time.sleep(1.0)
    with open(first, "w", encoding="utf-8") as fh:
        fh.write("one")
    time.sleep(0.4)
    with open(first, "a", encoding="utf-8") as fh:
        fh.write("two")
    time.sleep(0.4)
    os.replace(first, second)
    time.sleep(0.4)
    os.remove(second)
    log["files"] = True
    time.sleep(0.8)
    keep = IS_WIN and os.environ.get("BASTARD_SELFTEST_KEEP")
    if IS_WIN:
        registry_actions()
        log["registry"] = True
        if keep:
            etw_session_state(os.path.join(os.path.dirname(folder), "etw_session_during.txt"))
    time.sleep(0.5)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1.5)"])
    log["child_pid"] = child.pid
    child.wait()
    if IS_WIN:
        quick = subprocess.Popen(["cmd.exe", "/c", "exit 7"])
        log["quick_pid"] = quick.pid
        quick.wait()
        time.sleep(0.5)
        try:
            pad = subprocess.Popen(["notepad.exe"])
            log["notepad_pid"] = pad.pid
            time.sleep(3.0)
            pad.kill()
            pad.wait()
        except OSError as exc:
            log["notepad_error"] = str(exc)
        try:
            result = subprocess.run(["eventcreate", "/T", "WARNING", "/ID", "999", "/L", "APPLICATION", "/SO",
                                     "TraceSelfTest", "/D", "Trace self test event"], capture_output=True, text=True)
            log["eventcreate"] = result.returncode
            log["eventcreate_output"] = (result.stdout + result.stderr).strip()
        except OSError as exc:
            log["eventcreate_output"] = str(exc)
    end = time.time() + 12.0
    index = 0
    while time.time() < end:
        index += 1
        with open(os.path.join(folder, "tick.txt"), "w", encoding="utf-8") as fh:
            fh.write(str(index))
        time.sleep(0.5)
    if keep:
        etw_session_state(os.path.join(os.path.dirname(folder), "etw_session_end.txt"))


def check(result, log, returncode):
    events = result.get("events", [])
    status = result.get("status", {})
    checks = []

    def add(name, ok, hard=True, info=""):
        checks.append((name, bool(ok), hard, info))

    add("exit code is 0", returncode == 0, info=str(returncode))
    add("no internal errors", not result.get("errors"), info=" | ".join(result.get("errors", []))[:3000])
    add("trace log written", result.get("log_exists") and result.get("log_lines", 0) > 0, info=result.get("log_path"))
    add("trace log in time order", result.get("log_sorted"))
    add("CSV and JSON export", all((result.get("exports") or {}).values()) and len(result.get("exports") or {}) == 2)
    add("trace started", has(events, "Trace started", source="System"))
    add("trace stopped", has(events, "Trace stopped after", source="System"))
    add("file created", has(events, "File created", "x.txt", source="Files"))
    add("file renamed", has(events, "renamed", "x.txt", "y.txt", source="Files"))
    add("file deleted", has(events, "deleted", "y.txt", source="Files"))
    child = log.get("child_pid")
    add("process start seen", any(ev["source"] == "Processes" and ev["pid"] == child and ev["event"].startswith("Started")
                                  for ev in events), info=str(child))
    add("process exit seen", any(ev["source"] == "Processes" and ev["pid"] == child and ev["event"].startswith("Exited")
                                 for ev in events), info=str(child))
    add("marker placed", has(events, "Marker 1", source="System"))
    add("marker summary", any(ev["event"].startswith("Marker 1:") and ev["level"] == "Marker" and "ProcMon" not in ev["event"]
                              and "Trace Tools" not in ev["event"] for ev in events))
    add("list shows events", result.get("listed", 0) > 0, info=str(result.get("listed")))
    if IS_WIN:
        add("registry value changed", has(events, "TraceSelfTest", "[A]", "1 (0x1) -> 2 (0x2)", source="Registry"))
        add("registry value added", has(events, "TraceSelfTest", "[B] added", source="Registry"))
        add("registry key created", has(events, "TraceSelfTest\\Sub created", source="Registry"))
        add("registry value deleted", has(events, "TraceSelfTest", "[B] deleted", source="Registry"))
        add("registry key deleted", has(events, "TraceSelfTest\\Sub deleted", source="Registry"))
        add("event log entry", has(events, "Trace self test event", source="Event Log"),
            info=log.get("eventcreate_output", ""))
        add("wallpaper source ran", has(events, "Wallpaper at start", source="Wallpaper"))
        if result.get("admin"):
            quick = log.get("quick_pid")
            add("short process exit code", any(ev["source"] == "Processes" and ev["pid"] == quick
                                               and "exit code 7" in ev["event"] for ev in events), info=str(quick))
        note = (status.get("ProcMon") or ["", ""])[1]
        if has(events, "ProcMon: capturing", source="System"):
            add("ProcMon capture read", has(events, "ProcMon: read", source="System"))
            add("ProcMon saw the test key", has(events, "TraceSelfTest", source="ProcMon"))
        else:
            add("ProcMon not used", True, hard=False, info=note)
        add("window opened", has(events, "Window opened", source="Windows"), hard=False,
            info=(status.get("Windows") or ["", ""])[1])
    for extra in ("ETW", "WMI", "Probes", "Trace Tools"):
        state = status.get(extra) or ["", ""]
        add("%s source ran" % extra, state[0] not in ("", "failed"), hard=False,
            info="%s %s" % (state[0], state[1]))
    if IS_WIN and result.get("admin"):
        add("ETW saw the test files", result.get("etw_test_file"))
        add("ETW saw the test key", result.get("etw_test_key"), hard=False)
    return checks


def app_log_path():
    return os.path.join(os.environ.get("LOCALAPPDATA", ""), "Bastard", "Bastard.log")


def app_log_lines(marks, keep=6):
    try:
        with open(app_log_path(), "r", encoding="utf-8", errors="replace") as fh:
            found = [line.rstrip() for line in fh if any(mark in line for mark in marks)]
    except OSError:
        return []
    return found[-keep:]


def main(argv):
    if not argv:
        print("usage: run_selftest.py <Bastard.exe or bastard.pyw>")
        return 2
    target = os.path.abspath(argv[0])
    command = [target] if target.lower().endswith(".exe") else [sys.executable, target]
    work = tempfile.mkdtemp(prefix=WORK_PREFIX)
    result_path = os.path.join(work, "result.json")
    folder = os.path.join(work, "watched")
    os.makedirs(folder)
    if IS_WIN:
        prepare_registry()
    args = command + ["--selftest", result_path, "--watch-folder", folder, "--seconds", str(SECONDS),
                      "--marker-at", str(MARKER_AT)]
    if IS_WIN:
        args += ["--watch-key", "HKCU\\" + KEY]
    print("Running: " + subprocess.list2cmdline(args))
    started = time.time()
    proc = subprocess.Popen(args)
    log = {}
    try:
        if not wait_for(result_path + ".ready", proc, 120):
            print("Bastard did not report that the trace started")
            proc.kill()
            return 1
        print("Trace running after %.1f s" % (time.time() - started))
        run_actions(folder, log)
        try:
            returncode = proc.wait(timeout=SECONDS + 600)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("Bastard did not finish in time")
            return 1
    finally:
        if IS_WIN:
            cleanup_registry()
    print("Bastard finished after %.1f s with exit code %s" % (time.time() - started, returncode))
    if not os.path.isfile(result_path):
        print("Bastard wrote no result file")
        return 1
    with open(result_path, "r", encoding="utf-8") as fh:
        result = json.load(fh)
    print("Platform: %s, administrator: %s" % (result.get("platform"), result.get("admin")))
    for name, value in sorted(result.get("status", {}).items()):
        print("  %-10s %-9s %s" % (name, value[0], value[1]))
    for name, count in sorted(result.get("counts", {}).items()):
        print("  %-10s %d events" % (name, count))
    print("Actions: " + json.dumps(log))
    for line in app_log_lines(("ETW read", "ETW raw trace")):
        print("Bastard.log: " + line)
    failed = 0
    for name, ok, hard, info in check(result, log, returncode):
        mark = "PASS" if ok else ("FAIL" if hard else "NOTE")
        if not ok and hard:
            failed += 1
        print("%s  %s%s" % (mark, name, ("  [" + info + "]") if info and not ok else ""))
    if failed:
        print("Events seen:")
        for ev in result.get("events", [])[:400]:
            print("  %s %-10s %-8s %s" % (ev["time"][11:], ev["source"], ev["level"], ev["event"][:200]))
    keep = os.environ.get("BASTARD_SELFTEST_KEEP")
    if keep:
        os.makedirs(keep, exist_ok=True)
        for name in os.listdir(work):
            path = os.path.join(work, name)
            if os.path.isfile(path):
                shutil.copy2(path, os.path.join(keep, name))
        if result.get("log_path") and os.path.isfile(result["log_path"]):
            shutil.copy2(result["log_path"], os.path.join(keep, os.path.basename(result["log_path"])))
        app_log = app_log_path()
        if os.path.isfile(app_log):
            shutil.copy2(app_log, os.path.join(keep, "Bastard.log"))
    shutil.rmtree(work, ignore_errors=True)
    print("%d hard checks failed" % failed if failed else "All hard checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
