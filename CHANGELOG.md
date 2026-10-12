# Changelog

## 1.0.0

- Bastard 1.0.0 is a monitor: it watches and records what happens on the PC and never changes a setting, an app or Windows.
- Start begins a trace, Marker marks the moment you try something, and Stop ends the trace.
- Every trace shows registry, file, process, window, event log, ProcMon and wallpaper events in one timeline, in time order.
- Registry shows every change under the desktop, wallpaper, lock screen, theme, accent and personalization keys, before and after.
- Registry shows which picture the TranscodedImageCache value points to, instead of raw bytes.
- Files shows files created, changed, renamed or deleted in the Themes folders and the Photos app folder.
- Processes shows every program that starts or exits, with its parent and its command line.
- When Bastard runs as administrator, Processes also catches programs that live only a moment and shows their exit codes.
- Windows shows which window comes to the front and which windows and dialogs open, with the dialog text when it can be read.
- Event Log shows new entries from Application, System and the app, shell and task logs, plus the minute before Start.
- ProcMon records a capture when Procmon64.exe sits next to Bastard, and lists denied access, registry writes and file writes from it.
- ProcMon results appear in the timeline at the moment they happened, and Open in ProcMon opens the whole capture.
- Wallpaper shows the wallpaper Windows reports at Start and every change to it.
- Six seconds after a Marker, the timeline sums up what happened in that time, or says that nothing happened.
- Each trace is written live to a log on the Desktop and put in time order when the trace ends.
- The SOURCE and KIND filters, Show and Search narrow the timeline, and DETAILS shows everything about the selected event.
- Copy puts the selected events on the clipboard, and Export CSV and Export JSON save the events that match the filters.
- Stop never freezes the window: ProcMon results are read in the background while the ProcMon light shows the progress.
- Closing the window during a trace stops every source, ProcMon included.
- When it is not run as administrator, Bastard offers to restart as administrator, which ProcMon and short-lived processes need.
- The window remembers its size, position, divider and filters.
- F5 starts, Shift+F5 stops, F8 places a Marker, Ctrl+F jumps to Search, and Ctrl+S and Ctrl+J export.
