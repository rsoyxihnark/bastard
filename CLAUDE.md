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

`bastard.pyw` is a monitor: it watches and records, and never changes a
setting, an app or Windows. The archive under `OldDevelopments/` has
active repairs (shell verb restore, Photos re-register, a wallpaper test
write); they were left out on purpose. Ask before adding anything that
writes, even an idempotent write, because it softens that promise.

ETW, ProcMon and Trace Tools are the loud sources: a 32 second trace
produces over a million events from them while the signal worth finding is
a few hundred. The in-memory timeline caps their reads at four fifths of
its room so the quiet sources and every denial and write keep their place.
The log on the Desktop always holds the whole run.
