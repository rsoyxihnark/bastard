import ast
import io
import os
import re
import subprocess
import sys
import tokenize

LIMIT = 248
ENTRY_GOAL = 140
EXEMPT_PREFIXES = ("OldDevelopments/", "archive/", ".cl" "aude/")
EXEMPT_FILES = ("CL" "AUDE.md",)
TEXT_SUFFIXES = (".py", ".pyw", ".md", ".yml", ".yaml", ".txt", ".json", ".cfg", ".toml", ".ini", ".ps1", ".bat")
TEXT_NAMES = (".gitignore", ".gitattributes")
DASHES = {"\u2012": "figure dash", "\u2013": "en dash", "\u2014": "em dash", "\u2015": "horizontal bar"}
BANNED = ("cl" "aude", "anth" "ropic", "co-auth" "ored-by")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
VERSION_RE = re.compile(r'^VERSION = "(\d+\.\d+\.\d+)"\r?$', re.M)
HEADING_RE = re.compile(r"^## (.+?)\s*$")


def tracked_files(root):
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=root,
                         capture_output=True, text=True, check=True).stdout
    return sorted(set(line.strip() for line in out.splitlines() if line.strip()))


def is_text(path):
    name = os.path.basename(path)
    return name in TEXT_NAMES or name.lower().endswith(TEXT_SUFFIXES)


def exempt(path):
    return path.startswith(EXEMPT_PREFIXES) or path in EXEMPT_FILES


class Report:
    def __init__(self):
        self.errors = []
        self.notes = []

    def error(self, path, line, text):
        self.errors.append("%s:%s: %s" % (path, line, text))

    def note(self, path, line, text):
        self.notes.append("%s:%s: %s" % (path, line, text))


def check_text(path, text, report):
    for number, line in enumerate(text.splitlines(), 1):
        for char, name in DASHES.items():
            if char in line:
                report.error(path, number, "%s at column %d" % (name, line.index(char) + 1))
        low = line.lower()
        for word in BANNED:
            if word in low:
                report.error(path, number, "attribution word %r" % word)
        if EMAIL_RE.search(line):
            report.error(path, number, "email address %r" % EMAIL_RE.search(line).group(0))
        if path.lower().endswith((".md", ".txt")) and len(line) > LIMIT:
            report.error(path, number, "line is %d characters, the limit is %d" % (len(line), LIMIT))


def docstring_nodes(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                yield body[0]


def check_python(path, text, report):
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError) as exc:
        report.error(path, 0, "could not be read as Python: %s" % exc)
        return
    for token in tokens:
        if token.type == tokenize.COMMENT:
            report.error(path, token.start[0], "code comment")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        report.error(path, exc.lineno, "syntax error: %s" % exc.msg)
        return
    for node in docstring_nodes(tree):
        report.error(path, node.lineno, "docstring")
    inside = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            segment = ast.get_source_segment(text, node) or ""
            for part in ast.walk(node):
                inside.add(id(part))
            if len(segment) - 3 > LIMIT:
                report.error(path, node.lineno, "text is %d characters, the limit is %d" % (len(segment) - 3, LIMIT))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in inside:
            if len(node.value) > LIMIT:
                report.error(path, node.lineno, "text is %d characters, the limit is %d" % (len(node.value), LIMIT))
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        for name in names:
            if len(name) > LIMIT:
                report.error(path, getattr(node, "lineno", 0), "name is longer than %d characters" % LIMIT)


def check_program(path, text, report):
    for number, line in enumerate(text.splitlines(), 1):
        for column, char in enumerate(line, 1):
            if ord(char) > 126 or (ord(char) < 32 and char != "\t"):
                report.error(path, number, "character U+%04X at column %d is not plain ASCII" % (ord(char), column))
                break
    found = VERSION_RE.findall(text)
    if len(found) != 1:
        report.error(path, 0, "the source must hold exactly one VERSION line, found %d" % len(found))
    return found[0] if len(found) == 1 else None


def version_key(text):
    return tuple(int(part) for part in text.split("."))


def check_changelog(path, text, report, version):
    headings = []
    for number, line in enumerate(text.splitlines(), 1):
        match = HEADING_RE.match(line)
        if match:
            headings.append((number, match.group(1)))
        if line.startswith("- "):
            size = len(line) - 2
            if size > LIMIT:
                report.error(path, number, "entry is %d characters, the limit is %d" % (size, LIMIT))
            elif size > ENTRY_GOAL:
                report.note(path, number, "entry is %d characters, try to stay under %d" % (size, ENTRY_GOAL))
    names = [name for _, name in headings]
    versions = []
    for number, name in headings:
        if name == "Unreleased":
            if number != headings[0][0]:
                report.error(path, number, "the Unreleased section must be the first one")
            continue
        if not re.match(r"^\d+\.\d+\.\d+$", name):
            report.error(path, number, "section heading %r is neither a version nor Unreleased" % name)
            continue
        versions.append(name)
    if len(set(versions)) != len(versions):
        report.error(path, 0, "a version has more than one section")
    if versions != sorted(versions, key=version_key, reverse=True):
        report.error(path, 0, "versions are not listed newest first")
    if version and versions and versions[0] != version:
        report.error(path, 0, "the newest section is %s but the source says %s" % (versions[0], version))
    if version and version not in names:
        report.error(path, 0, "there is no section for the version in the source, %s" % version)


def main():
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                          check=True).stdout.strip()
    report = Report()
    version = None
    changelog = None
    checked = 0
    for path in tracked_files(root):
        if exempt(path) or not is_text(path):
            continue
        full = os.path.join(root, path)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8", newline="") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            report.error(path, 0, "not UTF-8 text")
            continue
        checked += 1
        check_text(path, text, report)
        if path.endswith((".py", ".pyw")):
            check_python(path, text, report)
        if path == "bastard.pyw":
            version = check_program(path, text, report)
        if path == "CHANGELOG.md":
            changelog = text
    if changelog is None:
        report.error("CHANGELOG.md", 0, "missing")
    else:
        check_changelog("CHANGELOG.md", changelog, report, version)
    for note in report.notes:
        print("note: " + note)
    for error in report.errors:
        print("error: " + error)
    print("Checked %d files: %d errors, %d notes" % (checked, len(report.errors), len(report.notes)))
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
