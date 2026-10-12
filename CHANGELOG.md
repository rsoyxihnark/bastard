# Changelog

## 1.3.0

- Bastard 1.3.0 leaves the repetitive noise out, keeps its files next to itself, and says what it is doing after Stop.
- A filter list decides what never reaches the timeline or the log, and it starts with the three streams that said least.
- ETW file events that carry only handles are left out, and the ones that name a file are kept.
- The reads ProcMon and Trace Tools list are left out, while every denial and every write they see is kept.
- Right click an event and Leave this match out writes a rule for events shaped like that one.
- The Filter button shows the whole list to read and to edit, and Back to the defaults restores it.
- The rules live in Exclusions.ini next to Bastard, so they last and can be edited without the program.
- The trace log is written next to Bastard now, instead of on the Desktop.
- The Options button sets how large the trace log may grow, 30 MB to begin with, and the log says where it stopped.
- The log holds everything the filter let through rather than every event, so the filter decides its size as well.
- ProcMon, Probes and Trace Tools turn green when they finish, instead of going grey as if they had never run.
- While a trace is finishing, the status line names the sources still reading what they captured.
- Open in ProcMon, Export CSV, Export JSON and Open log folder are gone from the bar, and Ctrl+S and Ctrl+J still export.

## 1.2.3

- Bastard 1.2.3 reads four more personalization policies and reports where the Desktop and AppData folders really are.
- Probes now read the Spotlight policy, which can hold the lock screen and the desktop image.
- Probes now read NoLockScreen and NoChangingLockScreen under the user, next to the machine ones they already read.
- Probes now read NoSaveSettings, which keeps Explorer from saving what the user changes.
- Probes now report the Desktop, AppData, Local AppData and Pictures folders, and warn when one is outside the user profile.
- A redirected Desktop or AppData folder moves the trace log and the theme folders Bastard watches, so it is worth seeing.

## 1.2.2

- Bastard 1.2.2 is the 1.2.1 fixes in a release: 1.2.1 was never published, because the release step stopped at its first check.
- The release step now accepts a merge at the head of a push, and takes the version from the commit that sets it.
- The release step no longer checks a merge commit message, which is made from the branch name rather than written by hand.
- Nothing in the program itself changed since 1.2.1.

## 1.2.1

- Bastard 1.2.1 keeps the quiet sources in the timeline when ETW, ProcMon and Trace Tools flood it.
- The reads from the loud sources can fill at most four fifths of the timeline, so the other events always have room.
- Denials and registry and file writes now keep their place in the timeline, however many reads arrive.
- Before this a flood could fill the timeline, and every later event, markers and Trace stopped included, was only in the log.
- A trace with a million events now finishes in seconds instead of minutes, because the timeline is put in time order when it is read.
- The self-test now reports every quiet event with a sample of each loud stream, instead of the first events by time.
- The log on the Desktop still keeps the whole run, as it did before.

## 1.2.0

- Bastard 1.2.0 lets the whole river through: ETW, ProcMon and Trace Tools now list every event, not only the personalization ones.
- ETW now lists every registry and file event it parses, whatever key or path it touches.
- ProcMon now lists every operation it captures, reads and lookups on every path, not only the personalization ones.
- ProcMon now also lists its network operations, next to the file, registry and process ones.
- Trace Tools now lists every row logman or WPR captured, not only the personalization ones.
- The timeline now holds up to a million events in memory, and the log on the Desktop still keeps the whole run.
- The kind filter has new Network, Trace and Probe buttons, so you can hide or show each stream yourself.
- Bastard still leaves out only its own work and the ProcMon helper, so the trace does not feed on itself.

## 1.1.0

- Bastard 1.1.0 reads every channel the earlier versions read and shows all of it unfiltered, so you can sift the noise yourself.
- ETW follows the Kernel-Registry, Kernel-File, Shell-Core, Immersive-Shell and Themes providers live and lists their events.
- ProcMon now also lists reads and lookups on the wallpaper, theme, Photos and lock screen paths, not only writes and denials.
- ProcMon no longer groups repeats, so every captured operation shows on its own line.
- Registry now also watches the LogonUI background, the ActivatableClasses packages, the Personalization policies and the System policies.
- Files now also watches the Explorer folder under Local AppData and reports every change the moment it arrives.
- Windows now records a line when a window is first created, on top of in front, opened, shown and closed.
- WMI reports new processes and wallpaper value changes the way Windows itself sees them.
- Probes reads the personalization and app privacy policies, the consent store, DisallowRun, image options, services and permissions at start.
- Probes reads the Set as desktop background menu entry, the image file associations and the Photos package name, version and status.
- Probes reads the lock screen image path and whether Windows still reports the wallpaper can be set.
- Trace Tools records the same providers with logman, or WPR when logman will not start, and reads them back with tracerpt.

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
