import json
import os
import re
import subprocess
import sys
import tempfile

HEADING_RE = re.compile(r"^## (.+?)\s*$")
TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")


def sections(text):
    out = {}
    current = None
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            current = match.group(1)
            out[current] = []
        elif current is not None and line.startswith("- "):
            out[current].append(line[2:].strip())
    return out


def notes(entries):
    return "\n".join("- " + entry for entry in entries) + "\n"


def body_lines(body):
    return [line.rstrip() for line in (body or "").replace("\r\n", "\n").strip().splitlines() if line.strip()]


def plan(changelog, releases):
    found = sections(changelog)
    changes = []
    missing = []
    for release in releases:
        match = TAG_RE.match(release.get("tag") or "")
        if not match or release.get("draft"):
            continue
        entries = found.get(match.group(1))
        if not entries:
            missing.append(release["tag"])
            continue
        if body_lines(release.get("body")) != ["- " + entry for entry in entries]:
            changes.append((release["tag"], notes(entries)))
    return changes, missing


def gh(*args):
    result = subprocess.run(["gh"] + list(args), capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError("gh %s failed: %s" % (args[0], result.stderr.strip()))
    return result.stdout


def published(repo):
    out = gh("api", "--paginate", "repos/%s/releases?per_page=100" % repo, "--jq",
             ".[] | {tag: .tag_name, body: .body, draft: .draft} | @json")
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def main(argv):
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        print("GITHUB_REPOSITORY is not set, so there is nothing to compare against")
        return 1
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "CHANGELOG.md"), "r", encoding="utf-8") as fh:
        changelog = fh.read()
    releases = published(repo)
    changes, missing = plan(changelog, releases)
    for tag in missing:
        print("note: %s has no section in CHANGELOG.md, so its notes are left as they are" % tag)
    dry = "--dry-run" in argv
    for tag, text in changes:
        if dry:
            print("would rewrite the notes of %s" % tag)
            continue
        handle, path = tempfile.mkstemp(suffix=".md")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            gh("release", "edit", tag, "--repo", repo, "--notes-file", path)
        finally:
            os.remove(path)
        print("rewrote the notes of %s" % tag)
    print("Checked %d releases: %d rewritten" % (len(releases), 0 if dry else len(changes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
