# Working notes for this repository

## How work is handed over

- Do not open pull requests. Commit and push straight to `main`.
  The release workflow only runs on a push to `main`, so a pull request
  leaves the owner a merge button to press and the release waiting. Leave
  no step for the owner.
- Push the work as a single commit on top of `main`, the way 1.0.0 through
  1.2.0 shipped. A merge commit is worse here: its subject is generated
  from the branch name, which breaks `tools/release_gate.py` twice over.
- Report what happened after the push, with the run and the release link.

## What the release gate demands

`tools/release_gate.py` runs first and skips every later step when it
fails, the self-test and the publish included.

- Subject must be `[x.y.z] ...` or `[no release] ...`.
- The body must be bullet points only, and must match the `CHANGELOG.md`
  section for that version word for word. Generate it from the changelog
  rather than retyping it.
- No attribution or co-author trailers in commit messages: the gate
  rejects the words in its own `BANNED` tuple, and a trailer also breaks
  the bullet-points-only rule. The earlier releases carry none.
- A version already present in `main`'s source can never be published
  again, so a failed release needs the next version number, not a retry.
- `tools/` , `.github/` and this file are exempt from the changelog rule,
  so a `[no release]` commit touching only those needs no entry.

## What the source rules demand

`tools/check_source.py` rejects code comments and docstrings in tracked
Python, non-ASCII in `bastard.pyw`, more than one `VERSION` line, and a
newest `CHANGELOG.md` section that does not equal `VERSION`. Changelog
entries should stay under 140 characters.

## Validating before a push

CI is Windows only and a red push costs a full cycle. Run all four
locally first:

    python3.12 tools/check_source.py
    python3.12 -m unittest discover -s tools -p "test_*.py"
    python3.12 -m pyflakes bastard.pyw tools
    python3.12 tools/release_gate.py --before origin/main --after HEAD --notes /tmp/notes.md

Use `python3.12`, not `python3`: `tkinter` is installed only for 3.12, and
`bastard.pyw` imports it at module level, so the tests cannot load the
module under any other interpreter. `pyflakes` needs a virtualenv, since
the system Python is externally managed.

The Windows self-test cannot run on Linux. To check timeline behaviour,
replay a realistic per-source event mix through the real `Store` instead
of trusting a reading of the code.

## The program itself

`bastard.pyw` is a monitor and it writes NOTHING outside its own files.
Reads of every kind are wanted; a write of any kind is not, not even zero
bytes, not even the same value written back. The owner settled this in
1.3.2: do not propose it again.

Its own files are the exception and are expected: the trace log, the
`Exclusions.ini`, `settings.json`, the exports, and the capture files
logman and ProcMon write into `TRACE_DIR`.

So: never `winreg.SetValue`, `CreateKey`, `DeleteKey` or `DeleteValue`,
never `KEY_SET_VALUE`, `KEY_WRITE` or `KEY_ALL_ACCESS`, never
`SPI_SETDESKWALLPAPER` or any `SPIF_` flag, never a binary or append open
on a file of Windows. `test_the_program_never_writes_to_windows` holds the
line; keep its list current rather than working around it.

To answer whether something is writable, read its rights instead: `icacls`
for a file path, and PowerShell `Get-Acl` for a registry path, because
`icacls` cannot read a registry path at all. The archive under
`OldDevelopments/` has active repairs and write probes; they stay out.

ETW, ProcMon and Trace Tools are the loud sources: unfiltered, a 32 second
trace produces over a million events from them while the signal worth
finding is a few hundred. Two things hold that back.

The in-memory timeline caps their reads at four fifths of its room, so the
quiet sources and every denial and write keep their place.

Since 1.3.0 a filter drops events at ingest, before the timeline and
before the log, driven by `Exclusions.ini` next to the program. Its rules
read `source | level | the text it holds | the text that keeps it`, and
the level is what separates noise from signal in the loud sources: `info`
is reads, `change` is writes, `error` is denials. The three defaults cut a
real CI run from 1,284,000 events to 15,439 and its self-test from 276 to
155 seconds, with all 30 hard checks still passing.

Never let a default rule catch anything `tools/run_selftest.py` checks
for; `test_default_exclusions_keep_what_the_selftest_looks_for` guards
that, so extend it when the defaults change. System events are exempt
from every rule.

The trace log is written next to the program, not to the Desktop, it holds
what the filter let through rather than the whole run, and the Options
button caps its size at 30 MB.
