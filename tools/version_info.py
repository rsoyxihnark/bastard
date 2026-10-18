import ctypes
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(os.path.dirname(HERE), "bastard.pyw")
VERSION_RE = re.compile(r'^VERSION = "(\d+\.\d+\.\d+)"\r?$', re.M)
PRODUCT = "Bastard"
FILE_NAME = "Bastard.exe"
LANGUAGE = "040904B0"
TRANSLATION = [1033, 1200]
DEFAULT_OUT = "version_info.txt"


def source_version(path=SOURCE):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    found = VERSION_RE.findall(text)
    if len(found) != 1:
        raise SystemExit("bastard.pyw must hold exactly one VERSION line, found %d" % len(found))
    return found[0]


def numbers(version):
    parts = [int(part) for part in version.split(".")]
    return tuple((parts + [0, 0, 0, 0])[:4])


def strings(version):
    return [("FileDescription", PRODUCT),
            ("FileVersion", version),
            ("InternalName", PRODUCT),
            ("OriginalFilename", FILE_NAME),
            ("ProductName", PRODUCT),
            ("ProductVersion", version)]


def version_file(version):
    fixed = numbers(version)
    table = ["          StringStruct('%s', '%s')," % pair for pair in strings(version)]
    table[-1] = table[-1].rstrip(",")
    lines = ["VSVersionInfo(",
             "  ffi=FixedFileInfo(",
             "    filevers=%s," % (fixed,),
             "    prodvers=%s," % (fixed,),
             "    mask=0x3f,",
             "    flags=0x0,",
             "    OS=0x40004,",
             "    fileType=0x1,",
             "    subtype=0x0,",
             "    date=(0, 0)",
             "  ),",
             "  kids=[",
             "    StringFileInfo([",
             "      StringTable(",
             "        '%s'," % LANGUAGE,
             "        ["]
    lines.extend(table)
    lines.extend(["        ])",
                  "    ]),",
                  "    VarFileInfo([VarStruct('Translation', %s)])" % TRANSLATION,
                  "  ]",
                  ")",
                  ""])
    return "\n".join(lines)


def stamp_of(path):
    if os.name != "nt":
        raise SystemExit("a version stamp can only be read on Windows")
    dll = ctypes.WinDLL("version", use_last_error=True)
    dll.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
    dll.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
    dll.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    dll.GetFileVersionInfoW.restype = ctypes.c_int
    dll.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
    dll.VerQueryValueW.restype = ctypes.c_int
    size = dll.GetFileVersionInfoSizeW(path, None)
    if not size:
        raise SystemExit("%s carries no version stamp" % path)
    data = ctypes.create_string_buffer(size)
    if not dll.GetFileVersionInfoW(path, 0, size, data):
        raise SystemExit("the version stamp on %s could not be read" % path)
    value = ctypes.c_void_p()
    length = ctypes.c_uint()
    query = "\\StringFileInfo\\%s\\FileVersion" % LANGUAGE
    if not dll.VerQueryValueW(data, query, ctypes.byref(value), ctypes.byref(length)) or not length.value:
        raise SystemExit("%s carries no FileVersion" % path)
    return ctypes.wstring_at(value.value, length.value).rstrip("\x00")


def after(argv, flag, fallback=None):
    if flag not in argv:
        return fallback
    index = argv.index(flag) + 1
    if index >= len(argv):
        raise SystemExit("%s needs a path after it" % flag)
    return argv[index]


def main(argv):
    version = source_version()
    if "--print" in argv:
        print(version)
        return 0
    target = after(argv, "--check")
    if target is not None:
        found = stamp_of(target)
        if found != version:
            print("error: %s says %s but the source says %s" % (target, found, version))
            return 1
        print("%s carries the version stamp %s" % (target, found))
        return 0
    out = after(argv, "--out", DEFAULT_OUT)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(version_file(version))
    print("Wrote %s for version %s" % (out, version))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
