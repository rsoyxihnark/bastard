import os
import re
import subprocess
import sys

SUBJECT_RE = re.compile(r"^\[(\d+\.\d+\.\d+|no release)\] \S")
VERSION_RE = re.compile(r'^VERSION = "(\d+\.\d+\.\d+)"\r?$', re.M)
HEADING_RE = re.compile(r"^## (.+?)\s*$")
EXEMPT_PREFIXES = ("tools/", ".github/", ".cl" "aude/", "OldDevelopments/", "archive/")
EXEMPT_FILES = ("CL" "AUDE.md", "README.md", "COMPARISON.md", ".gitignore")
BANNED = ("cl" "aude", "anth" "ropic", "co-auth" "ored-by")
DASHES = ("\u2012", "\u2013", "\u2014", "\u2015")
LIMIT = 248
EMPTY = "0" * 40


def git(*args):
    result = subprocess.run(["git"] + list(args), capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), result.stderr.strip()))
    return result.stdout


def file_at(commit, path):
    try:
        return git("show", "%s:%s" % (commit, path))
    except RuntimeError:
        return None


def source_version(commit):
    text = file_at(commit, "bastard.pyw")
    if text is None:
        return None
    found = VERSION_RE.findall(text)
    return found[0] if len(found) == 1 else "unreadable"


def sections(text):
    out = []
    current = None
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            current = [match.group(1), []]
            out.append(current)
        elif current is not None and line.startswith("- "):
            current[1].append(line[2:].strip())
    return out


def body_lines(body):
    return [line.rstrip() for line in body.strip().splitlines() if line.strip()]


def commit_range(before, after):
    if before and before != EMPTY:
        try:
            git("cat-file", "-e", before + "^{commit}")
            listed = git("rev-list", "--reverse", "%s..%s" % (before, after)).split()
            if listed:
                return listed
        except RuntimeError:
            pass
    return [git("rev-parse", after).strip()]


def check_message(subject, body, problems):
    message = subject + "\n" + body
    low = message.lower()
    for word in BANNED:
        if word in low:
            problems.append("the commit message names %r" % word)
    for dash in DASHES:
        if dash in message:
            problems.append("the commit message holds the dash U+%04X" % ord(dash))
    for line in [subject] + body_lines(body):
        if len(line) > LIMIT:
            problems.append("a commit message line is %d characters, the limit is %d" % (len(line), LIMIT))
    if not SUBJECT_RE.match(subject):
        problems.append("the subject must start with [x.y.z] or [no release]: %r" % subject)


def check_commit(commit, problems):
    parents = git("log", "-1", "--format=%P", commit).split()
    if len(parents) > 1:
        return None
    subject = git("log", "-1", "--format=%s", commit).strip()
    body = git("log", "-1", "--format=%b", commit)
    files = [line for line in git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commit).splitlines()
             if line.strip()]
    parent = parents[0] if parents else None
    check_message(subject, body, problems)
    match = SUBJECT_RE.match(subject)
    if not match:
        return None
    version = source_version(commit)
    before = source_version(parent) if parent else None
    if match.group(1) == "no release":
        if parent is not None and version != before:
            problems.append("a [no release] commit changes the version from %s to %s" % (before, version))
        if "CHANGELOG.md" not in files:
            program = [path for path in files if not (path.startswith(EXEMPT_PREFIXES) or path in EXEMPT_FILES)]
            if program:
                problems.append("a commit that changes %s writes nothing into CHANGELOG.md" % ", ".join(program))
        return None
    wanted = match.group(1)
    if "CHANGELOG.md" not in files:
        problems.append("version %s leaves CHANGELOG.md untouched" % wanted)
    if version != wanted:
        problems.append("the subject says %s but the source says %s" % (wanted, version))
    if before == wanted:
        problems.append("version %s was already in the source before this commit" % wanted)
    changelog = file_at(commit, "CHANGELOG.md") or ""
    found = sections(changelog)
    names = [name for name, _ in found]
    if "Unreleased" in names:
        problems.append("a version commit leaves an Unreleased section behind")
    if not found or found[0][0] != wanted:
        problems.append("the newest CHANGELOG.md section is %s, not %s" % (found[0][0] if found else "missing", wanted))
    entries = found[0][1] if found and found[0][0] == wanted else []
    if not entries:
        problems.append("the CHANGELOG.md section for %s has no entries" % wanted)
    lines = body_lines(body)
    if any(not line.startswith("- ") for line in lines):
        problems.append("the commit body must be bullet points only")
    if [line[2:].strip() for line in lines] != entries:
        problems.append("the commit body and the CHANGELOG.md section for %s do not say the same thing" % wanted)
    if git("tag", "-l", "v" + wanted).strip():
        problems.append("version %s has already been released" % wanted)
    return wanted, body.strip()


def main(argv):
    options = {"--before": "", "--after": "HEAD", "--notes": "release_notes.md"}
    index = 0
    while index < len(argv):
        if argv[index] in options and index + 1 < len(argv):
            options[argv[index]] = argv[index + 1]
            index += 2
        else:
            index += 1
    commits = commit_range(options["--before"].strip(), options["--after"].strip())
    head = git("rev-parse", options["--after"].strip()).strip()
    problems = []
    publish = None
    shipped_at = []
    for commit in commits:
        found = []
        shipped = check_commit(commit, found)
        for problem in found:
            problems.append("%s: %s" % (commit[:8], problem))
        if shipped:
            shipped_at.append((commit, shipped))
    left = source_version(head)
    for commit, shipped in shipped_at:
        if shipped[0] != left:
            print("note: %s: version %s is not what this push leaves behind, so it is skipped" % (
                commit[:8], shipped[0]))
        elif publish:
            problems.append("%s: version %s is set by more than one commit in this push" % (
                commit[:8], shipped[0]))
        else:
            publish = shipped
    print("Checked %d commit(s)" % len(commits))
    for problem in problems:
        print("error: " + problem)
    outputs = os.environ.get("GITHUB_OUTPUT")
    if problems:
        return 1
    if publish:
        with open(options["--notes"], "w", encoding="utf-8", newline="\n") as fh:
            fh.write(publish[1] + "\n")
        print("Version %s will be published" % publish[0])
    else:
        print("Nothing to publish")
    if outputs:
        with open(outputs, "a", encoding="utf-8") as fh:
            fh.write("publish=%s\n" % ("true" if publish else "false"))
            fh.write("version=%s\n" % (publish[0] if publish else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
